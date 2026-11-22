import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const core = "urn:ietf:params:jmap:core";
const mail = "urn:ietf:params:jmap:mail";
const submission = "urn:ietf:params:jmap:submission";
const using = [core, mail, submission];
const sessionUrl = new URL(process.env.JMAP_SESSION_URL);
const emulator = process.env.JMAP_EMULATOR === "1";
const token = process.env.JMAP_TOKEN;
const recipient = process.env.JMAP_RECIPIENT;
const scenario = process.env.JMAP_SCENARIO ?? "delivery";
const fileAfterSend = scenario === "post-submit-actions";
const sendStored = scenario === "stored-email";
const reuseCreationIDs = scenario === "creation-ids";
const autosaveDraft = scenario === "draft-autosave";
const syncQueryTies = scenario === "query-ties";
const checkGetContract = scenario === "get-contract";
const destroySubmission = scenario === "destroy-submission";
const writeDraftHeaders = scenario === "draft-headers";
const forwardAttachment = scenario === "forward-attachment";
const explicitEnvelope = scenario === "explicit-envelope";
const requestDSN = scenario === "dsn-envelope";
const multipleRecipients = explicitEnvelope || scenario === "derived-envelope";
const secondRecipient = process.env.JMAP_SECOND_RECIPIENT;
const visibleRecipient = explicitEnvelope ? process.env.JMAP_HEADER_RECIPIENT : recipient;

assert.ok(recipient, "Set JMAP_RECIPIENT to a controlled address");
assert.ok(emulator || (token && sessionUrl.protocol === "https:"),
  "Set JMAP_TOKEN and use an HTTPS session URL");
assert.ok(["delivery", "post-submit-actions", "derived-envelope", "explicit-envelope", "dsn-envelope", "stored-email", "creation-ids", "draft-autosave", "query-ties", "get-contract", "destroy-submission", "draft-headers", "forward-attachment",
  "smtp-rejection", "smtp-unavailable", "imap-unavailable", "smtp-ambiguous"].includes(scenario));
assert.ok(!(fileAfterSend || multipleRecipients || requestDSN || sendStored || reuseCreationIDs || autosaveDraft || syncQueryTies || checkGetContract || destroySubmission || writeDraftHeaders || forwardAttachment) || !emulator, "This scenario requires the gateway");
if (multipleRecipients) assert.ok(secondRecipient && secondRecipient !== recipient, "Set a second controlled recipient");
if (explicitEnvelope) assert.ok(visibleRecipient && ![recipient, secondRecipient].includes(visibleRecipient), "Set a separate To header address");

async function request(url, data, authenticated = true) {
  return fetch(url, {
    method: data ? "POST" : "GET",
    headers: {
      ...(data ? { "Content-Type": "application/json" } : {}),
      ...(authenticated && token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: data && JSON.stringify(data),
    redirect: "error",
    signal: AbortSignal.timeout(90000),
  });
}

async function readJSON(response) {
  assert.equal(response.status, 200, "Expected HTTP 200");
  return response.json();
}

if (!emulator) assert.equal((await request(sessionUrl, null, false)).status, 401);
const session = await readJSON(await request(sessionUrl));
const api = new URL(session.apiUrl);
assert.equal(api.origin, sessionUrl.origin);
for (const capability of using) assert.ok(Object.hasOwn(session.capabilities, capability));
const accountId = session.primaryAccounts[mail];
assert.ok(accountId && accountId === session.primaryAccounts[submission]);
if (requestDSN) assert.deepEqual(session.accounts[accountId].accountCapabilities[submission].submissionExtensions.DSN, []);
async function call(methodCalls) {
  return (await readJSON(await request(api, { using, methodCalls }))).methodResponses;
}
function result(responses, id, method) {
  const entry = responses.find(([, , tag]) => tag === id);
  assert.equal(entry?.[0], method, `Unexpected method response for ${id}: ${entry?.[1]?.type ?? "missing"}`);
  return entry[1];
}

if (!emulator) {
  assert.equal((await request(api, { using, methodCalls: [] }, false)).status, 401);
}
const discovered = await call([
  ...(checkGetContract
    ? [["Mailbox/query", { accountId, filter: { hasAnyRole: true } }, "role-ids"],
      ["Mailbox/get", { accountId, "#ids": { resultOf: "role-ids", name: "Mailbox/query", path: "/ids" } }, "folders"]]
    : [["Mailbox/get", { accountId }, "folders"]]),
  ["Identity/get", { accountId }, "identities"],
]);
if (scenario === "imap-unavailable") {
  assert.equal(result(discovered, "folders", "error").type, "serverUnavailable");
  assert.ok(result(discovered, "identities", "Identity/get").list[0]?.id);
  console.log("Unauthorized requests and IMAP outage verified");
  process.exit(0);
}
const folders = result(discovered, "folders", "Mailbox/get").list;
const drafts = folders.find(({ role }) => role === "drafts")?.id;
const inbox = folders.find(({ role }) => role === "inbox")?.id;
const identity = result(discovered, "identities", "Identity/get").list[0];
assert.ok(drafts && inbox && identity?.id);
if (checkGetContract) {
  const limit = session.capabilities[core].maxObjectsInGet;
  const listed = await call([
    ["Mailbox/query", { accountId, limit, calculateTotal: true }, "query"],
    ["Mailbox/get", { accountId, "#ids": { resultOf: "query", name: "Mailbox/query", path: "/ids" },
      properties: ["name"] }, "page"],
    ["Mailbox/get", { accountId, ids: null }, "all"],
    ["Mailbox/get", { accountId, ids: Array(limit + 1).fill(inbox) }, "oversize"],
    ["Mailbox/get", { accountId, ids: [inbox, inbox, "missing-fixture", "missing-fixture"], properties: [] }, "dedup"],
    ["Mailbox/get", { accountId, ids: [], properties: ["invalidFixtureProperty"] }, "invalid-mailbox-property"],
    ["Email/get", { accountId, ids: [], bodyProperties: ["invalidFixtureProperty"] }, "invalid-part-property"],
    ["Email/get", { accountId, ids: [null] }, "invalid-id"],
    ["Thread/get", { accountId, ids: [], properties: ["size"] }, "invalid-thread-property"],
    ["EmailSubmission/get", { accountId, ids: [], Properties: ["id"] }, "invalid-argument-case"],
  ]);
  const query = result(listed, "query", "Mailbox/query");
  assert.ok(query.total > limit, "Create more selectable test mailboxes than maxObjectsInGet");
  assert.equal(query.ids.length, limit);
  const page = result(listed, "page", "Mailbox/get");
  assert.deepEqual(page.list.map(({ id }) => id), query.ids);
  assert.ok(page.list.every((mailbox) => Object.keys(mailbox).length === 2));
  for (const tag of ["all", "oversize"]) assert.equal(result(listed, tag, "error").type, "requestTooLarge");
  const unique = result(listed, "dedup", "Mailbox/get");
  assert.deepEqual(unique.list, [{ id: inbox }]);
  assert.deepEqual(unique.notFound, ["missing-fixture"]);
  for (const tag of ["invalid-mailbox-property", "invalid-part-property", "invalid-id", "invalid-thread-property", "invalid-argument-case"]) {
    assert.equal(result(listed, tag, "error").type, "invalidArguments");
  }
  console.log("Verified Get property validation, deduplication and paging to the advertised limit");
}
const marker = `JMAP acceptance ${randomUUID()}`;
const body = `This message verifies ${marker}.`;
if (syncQueryTies) {
  const subject = `Query ties ${marker}`;
  async function uploadFixture(prefix) {
    const uploaded = await fetch(session.uploadUrl.replace("{accountId}", accountId), {
      method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "message/rfc822" },
      body: `Subject: ${prefix} ${subject}\r\n\r\nQuery fixture.\r\n`, redirect: "error", signal: AbortSignal.timeout(90000),
    });
    assert.equal(uploaded.status, 201);
    return (await uploaded.json()).blobId;
  }
  const [upper, lower] = await Promise.all([uploadFixture("Ä"), uploadFixture("ä")]);
  const query = { accountId, filter: { subject }, sort: [{ property: "receivedAt", isAscending: false }] };
  const at = (receivedAt, blobId = upper) => ({ blobId, mailboxIds: { [inbox]: true }, receivedAt });
  const fixture = await call([
    ["Mailbox/set", { accountId, create: { target: { name: subject } } }, "target"],
    ["Email/import", { accountId, emails: {
      first: at("2026-01-01T00:00:00Z"), second: at("2026-01-01T00:00:00Z"),
    } }, "import"],
    ["Email/query", query, "before"],
  ]);
  const target = result(fixture, "target", "Mailbox/set").created.target.id;
  const { first, second } = result(fixture, "import", "Email/import").created;
  const before = result(fixture, "before", "Email/query");
  assert.deepEqual(before.ids, [first.id, second.id].sort());
  const moving = inbox < target ? second.id : first.id;
  const moved = await call([["Email/set", {
    accountId, update: { [moving]: { mailboxIds: { [target]: true } } },
  }, "move"]]);
  assert.ok(Object.hasOwn(result(moved, "move", "Email/set").updated, moving));
  const observed = await call([
    ["Email/get", { accountId, ids: [moving], properties: ["mailboxIds"] }, "moved"],
    ["Email/query", { ...query, anchor: before.ids.at(-1), anchorOffset: -1 }, "window"],
    ["Email/import", { accountId, emails: {
      newer: at("2026-01-02T00:00:00Z", lower), older: at("2025-12-31T00:00:00Z"),
    } }, "bounds"],
    ["Email/queryChanges", {
      ...query, sinceQueryState: before.queryState, upToId: before.ids.at(-1), maxChanges: 1,
    }, "delta"],
    ["Email/query", { ...query, sort: [{ property: "subject" }, ...query.sort] }, "unicode"],
    ["Email/query", { ...query, sort: [{ property: "subject", collation: "i;ascii-casemap" }, ...query.sort] }, "ascii"],
  ]);
  assert.deepEqual(result(observed, "moved", "Email/get").list[0].mailboxIds, { [target]: true });
  const window = result(observed, "window", "Email/query");
  assert.deepEqual(window.ids, before.ids);
  assert.equal(window.queryState, before.queryState);
  const { newer, older } = result(observed, "bounds", "Email/import").created;
  const delta = result(observed, "delta", "Email/queryChanges");
  assert.deepEqual(delta.removed, []);
  assert.deepEqual(delta.added, [{ id: newer.id, index: 0 }]);
  assert.deepEqual(result(observed, "unicode", "Email/query").ids, [newer.id, ...before.ids, older.id]);
  assert.deepEqual(result(observed, "ascii", "Email/query").ids, [...before.ids, older.id, newer.id]);
  console.log("Verified stable query ties after IMAP MOVE, a sparse anchored delta and Unicode sorting");
}
let draftFolder = drafts;
if (autosaveDraft) {
  const saved = await call([
    ["Mailbox/set", { accountId, create: { work: { name: `Work ${marker}` } } }, "work"],
    ["Email/set", { accountId, create: { partial: {
      mailboxIds: { "#work": true }, keywords: { $draft: true, "$Flagged": true, Custom: true },
      subject: `Incomplete ${marker}`, "header:To": " unfinished@",
    } } }, "save"],
    ["EmailSubmission/set", { accountId, create: { premature: {
      emailId: "#partial", identityId: identity.id,
    } } }, "premature"],
  ]);
  draftFolder = result(saved, "work", "Mailbox/set").created.work.id;
  const partialID = result(saved, "save", "Email/set").created.partial.id;
  const rejected = result(saved, "premature", "EmailSubmission/set").notCreated.premature;
  assert.equal(rejected.type, "invalidEmail");
  assert.deepEqual(rejected.properties, ["from"]);
  const fetched = await call([["Email/get", {
    accountId, ids: [partialID], fetchTextBodyValues: true,
    properties: ["mailboxIds", "keywords", "messageId", "sentAt", "bodyValues", "header:To"],
  }, "saved"]]);
  const [partial] = result(fetched, "saved", "Email/get").list;
  assert.deepEqual(partial.mailboxIds, { [draftFolder]: true });
  assert.deepEqual(partial.keywords, { $draft: true, $flagged: true, custom: true });
  assert.ok(partial.messageId?.length && partial.sentAt);
  assert.equal(partial["header:To"], " unfinished@");
  assert.deepEqual(Object.values(partial.bodyValues).map(({ value }) => value), [""]);
  console.log("Verified incomplete draft in a custom IMAP mailbox and rejected premature submission");
}
let sent;
if (fileAfterSend) {
  const folders = await call([["Mailbox/set", {
    accountId, create: { sent: { name: `Sent ${marker}` } },
  }, "create-sent"]]);
  sent = result(folders, "create-sent", "Mailbox/set").created?.sent?.id;
  assert.ok(sent, "Expected an IMAP destination for the accepted draft");
}
const draft = {
  mailboxIds: { [reuseCreationIDs ? "#message" : draftFolder]: true },
  keywords: { $draft: true },
  from: [{ email: identity.email }],
  to: [{ email: visibleRecipient }],
  ...(multipleRecipients && { cc: [{ email: visibleRecipient }], bcc: [{ email: secondRecipient }] }),
  subject: marker,
  textBody: [{ partId: "1", type: "text/plain" }],
  bodyValues: { "1": { value: body } },
};
const draftHeaderTrace = [" first", " second\r\n continued"];
const draftMessageID = marker.split(" ").at(-1) + "@jmap.test";
if (writeDraftHeaders) {
  const rejected = await call([["Email/set", {
    accountId, create: { invalid: { ...draft, "header:X-JMAP-Trace": " invalid\r\nBcc: forged@example.test" } },
  }, "unsafe"]]);
  assert.equal(result(rejected, "unsafe", "Email/set").notCreated?.invalid?.type, "invalidProperties");
  delete draft.from;
  delete draft.to;
  Object.assign(draft, {
    "header:From": " " + identity.email,
    "header:To:asGroupedAddresses": [{ name: null, addresses: [{ email: recipient }] }],
    "header:X-JMAP-Trace:all": draftHeaderTrace,
    "header:List-Id:asText": "Postin otsaketesti",
    messageId: [draftMessageID],
    sentAt: "2026-11-22T12:15:00+02:00",
  });
  const uploaded = await fetch(session.uploadUrl.replace("{accountId}", accountId), {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream" },
    body: new Uint8Array([0, 13, 10, 127, 128, 255]), redirect: "error", signal: AbortSignal.timeout(90000),
  });
  assert.equal(uploaded.status, 201);
  const { blobId } = await uploaded.json();
  delete draft.textBody;
  draft.bodyStructure = {
    "header:Content-Type": " multipart/mixed; boundary=caller-boundary",
    subParts: [
      { partId: "1", "header:Content-Type": " text/plain; format=flowed" },
      { blobId, "header:Content-Type": " application/octet-stream",
        "header:Content-Disposition": " attachment; filename=fixture.bin",
        "header:Content-Description:asText": "Liite ää",
        "header:X-Part-Trace:all": [" first", " second\r\n continued"] },
    ],
  };
}
const embeddedFormat = process.env.JMAP_EMBEDDED_FORMAT ?? "7bit";
const embeddedType = embeddedFormat === "global" ? "message/global" : "message/rfc822";
const embeddedSubject = (embeddedFormat === "global" ? "Välitetty " : "Forwarded ") + marker;
let embeddedSource;
if (forwardAttachment) {
  assert.ok(["7bit", "8bit", "global"].includes(embeddedFormat));
  embeddedSource = [
    "From: archived@example.test",
    "Subject: " + embeddedSubject,
    "Bcc: original-private@example.test",
    "Content-Type: text/plain" + (embeddedFormat === "7bit" ? "" : "; charset=utf-8"),
    ...(embeddedFormat === "7bit" ? [] : ["Content-Transfer-Encoding: 8bit"]),
    "", embeddedFormat === "7bit" ? ".Original archived text." : ".Alkuperäinen teksti.", "",
  ].join("\r\n");
  const uploaded = await fetch(session.uploadUrl.replace("{accountId}", accountId), {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": embeddedType },
    body: embeddedSource, redirect: "error", signal: AbortSignal.timeout(90000),
  });
  assert.equal(uploaded.status, 201);
  const { blobId } = await uploaded.json();
  const imported = await call([["Email/import", {
    accountId, emails: { original: { blobId, mailboxIds: { [inbox]: true } } },
  }, "import-original"]]);
  const original = result(imported, "import-original", "Email/import").created.original;
  draft.attachments = [{ blobId: original.blobId, type: embeddedType, name: "forwarded.eml" }];
}
const find = (inMailbox) => ["Email/query", {
  accountId, filter: { inMailbox }, sort: [{ property: "receivedAt", isAscending: false }], limit: 20,
}, "query"];
const read = ["Email/get", {
  accountId, "#ids": { resultOf: "query", name: "Email/query", path: "/ids" }, fetchTextBodyValues: true,
}, "read"];
const envelopeID = `JMAP DSN =+ ${marker.split(" ").at(-1)}`;
const envelope = explicitEnvelope ? {
  mailFrom: { email: identity.email, parameters: null },
  rcptTo: [secondRecipient, recipient].map(email => ({ email, parameters: null })),
} : requestDSN ? {
  mailFrom: { email: identity.email, parameters: { envid: envelopeID, ret: "hdrs" } },
  rcptTo: [{ email: recipient, parameters: { notify: "failure,success", orcpt: `rfc822;${recipient}` } }],
} : null;
let creation = ["Email/set", { accountId, create: { message: draft } }, "create"];
if (sendStored) {
  const raw = [
    `From: ${identity.email}`, `To: ${recipient}`, `Date: ${new Date().toUTCString()}`,
    `Subject: ${marker}`, "", body, "",
  ].join("\r\n");
  const uploaded = await fetch(session.uploadUrl.replace("{accountId}", accountId), {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "message/rfc822" },
    body: raw, redirect: "error", signal: AbortSignal.timeout(90000),
  });
  assert.equal(uploaded.status, 201);
  const { blobId } = await uploaded.json();
  creation = ["Email/import", { accountId, emails: {
    message: { blobId, mailboxIds: { [inbox]: true } },
    copy: { blobId, mailboxIds: { [drafts]: true } },
  } }, "create"];
}
const failedReuse = ["Email/set", {
  accountId, create: { message: { ...draft, mailboxIds: { "#missing": true } } },
}, "failed-reuse"];
const submissionKey = reuseCreationIDs ? "message" : "submit";
const methodCalls = [
  creation,
  find(sendStored ? inbox : draftFolder), read,
  ...(reuseCreationIDs ? [failedReuse] : []),
  ["EmailSubmission/set", {
    accountId, create: { [submissionKey]: { emailId: "#message", identityId: identity.id, ...(envelope && { envelope }) } },
    ...(fileAfterSend && { onSuccessUpdateEmail: {
      "#submit": { [`mailboxIds/${drafts}`]: null, [`mailboxIds/${sent}`]: true, "keywords/$draft": null },
    } }),
  }, "submit"],
  ...(reuseCreationIDs ? [["EmailSubmission/get", { accountId, ids: ["#message"] }, "created-submission"]] : []),
];
const response = await readJSON(await request(api, {
  using, methodCalls, ...(reuseCreationIDs && { createdIds: { message: drafts, keep: inbox } }),
}));
const flow = response.methodResponses;
const created = result(flow, "create", creation[0]).created;
const emailId = created?.message?.id;
assert.ok(emailId);
assert.ok(result(flow, "query", "Email/query").ids.includes(emailId));
const message = result(flow, "read", "Email/get").list.find(({ id }) => id === emailId);
function checkMessage(message) {
  assert.ok(message?.subject === marker, "Expected unique subject");
  assert.ok(message.to?.[0]?.email === visibleRecipient, "Expected To header");
  assert.ok(Object.values(message.bodyValues).some(({ value }) => value.trimEnd() === body),
    "Expected plain-text body");
}
checkMessage(message);
if (sendStored) {
  assert.ok(!message.keywords.$draft);
  assert.ok(created.copy?.id && created.copy.id !== emailId);
}
if (multipleRecipients) assert.equal(message.bcc?.[0]?.email, secondRecipient);
const outcome = result(flow, "submit", "EmailSubmission/set");
async function replay(id = emailId) {
  const response = await call([["EmailSubmission/set", {
    accountId, create: { retry: { emailId: id, identityId: identity.id, ...(envelope && { envelope }) } },
  }, "replay"]]);
  return result(response, "replay", "EmailSubmission/set");
}
if (["smtp-rejection", "smtp-unavailable", "smtp-ambiguous"].includes(scenario)) {
  const expected = {
    "smtp-rejection": "invalidRecipients",
    "smtp-unavailable": "serverUnavailable",
    "smtp-ambiguous": "serverFail",
  }[scenario];
  assert.equal(outcome.notCreated?.submit?.type, expected);
  assert.ok(!outcome.created?.submit);
  if (scenario === "smtp-rejection") {
    assert.deepEqual(outcome.notCreated.submit.invalidRecipients, [recipient]);
  }
  if (scenario === "smtp-ambiguous") {
    assert.match(outcome.notCreated.submit.description, /acceptance is unknown/);
    assert.match((await replay()).notCreated?.retry?.description ?? "", /blocked from resubmission/);
    console.log(`Uncertain ${marker}`);
  }
  console.log(`Verified ${scenario}`);
  process.exit(0);
}
if (forwardAttachment && process.env.JMAP_EXPECT_SMTP_UTF8_REJECTION === "1") {
  assert.equal(embeddedFormat, "global");
  assert.equal(outcome.notCreated?.submit?.type, "forbiddenToSend");
  assert.match(outcome.notCreated.submit.description, /SMTPUTF8/);
  assert.match((await replay()).notCreated?.retry?.description ?? "", /SMTPUTF8/);
  console.log("Verified permanent pre-DATA rejection while SMTPUTF8 is unavailable");
  process.exit(0);
}
const submitted = outcome.created?.[submissionKey]?.id;
assert.ok(submitted, `Expected SMTP acceptance, got ${outcome.notCreated?.[submissionKey]?.type ?? "no result"}`);
if (reuseCreationIDs) {
  assert.equal(result(flow, "failed-reuse", "Email/set").notCreated?.message?.type, "invalidProperties");
  assert.notEqual(emailId, drafts);
  assert.notEqual(submitted, emailId);
  assert.deepEqual(response.createdIds, { message: submitted, keep: inbox });
  const [record] = result(flow, "created-submission", "EmailSubmission/get").list;
  assert.equal(record.id, submitted);
  assert.equal(record.emailId, emailId);
  console.log("Verified latest successful creation references across mailbox, email and submission IDs");
}
if (fileAfterSend) {
  const [method, filed, tag] = flow[flow.findIndex(([, , id]) => id === "submit") + 1];
  assert.equal(method, "Email/set");
  assert.equal(tag, "submit");
  assert.ok(Object.hasOwn(filed.updated, emailId));
  const lookup = await call([["Email/get", { accountId, ids: [emailId], fetchTextBodyValues: true }, "filed"]]);
  const message = result(lookup, "filed", "Email/get").list[0];
  assert.deepEqual(message.mailboxIds, { [sent]: true });
  assert.ok(!message.keywords.$draft);
  checkMessage(message);
  console.log("Verified automatic filing after SMTP acceptance");
}
if (!emulator) {
  const lookup = await call([["EmailSubmission/get", { accountId, ids: [submitted] }, "status"]]);
  const record = result(lookup, "status", "EmailSubmission/get").list[0];
  assert.equal(record?.undoStatus, "final");
  const expectedRecipients = explicitEnvelope ? [secondRecipient, recipient]
    : multipleRecipients ? [recipient, secondRecipient] : [recipient];
  assert.deepEqual(record.envelope.rcptTo.map(({ email }) => email), expectedRecipients);
  assert.deepEqual(Object.keys(record.deliveryStatus).sort(), [...expectedRecipients].sort());
  for (const { smtpReply, delivered, displayed } of Object.values(record.deliveryStatus)) {
    assert.match(smtpReply, /^25[0-9](?: |$)/);
    assert.equal(delivered, "unknown");
    assert.equal(displayed, "unknown");
  }
  if (requestDSN) {
    assert.deepEqual(record.envelope.mailFrom.parameters, { ENVID: envelopeID, RET: "HDRS" });
    assert.deepEqual(record.envelope.rcptTo[0].parameters, { NOTIFY: "SUCCESS,FAILURE", ORCPT: `rfc822;${recipient}` });
    console.log("Verified JMAP DSN advertisement, SMTP acceptance and decoded envelope options");
  }
  assert.equal((await replay()).created?.retry?.id, submitted);
  if (sendStored) assert.equal((await replay(created.copy.id)).created?.retry?.id, submitted);
}
if (writeDraftHeaders) {
  const stored = await call([["Email/get", { accountId, ids: [emailId],
    properties: ["header:X-JMAP-Trace:all", "header:List-Id:asText", "messageId", "sentAt", "bodyStructure"],
    bodyProperties: ["type", "charset", "name", "header:Content-Type", "header:Content-Description:asText", "header:X-Part-Trace:all"],
  }, "header-round-trip"]]);
  const [record] = result(stored, "header-round-trip", "Email/get").list;
  assert.deepEqual(record["header:X-JMAP-Trace:all"], draftHeaderTrace);
  assert.equal(record["header:List-Id:asText"], "Postin otsaketesti");
  assert.deepEqual(record.messageId, [draftMessageID]);
  assert.equal(record.sentAt, draft.sentAt);
  const [text, attachment] = record.bodyStructure.subParts;
  assert.equal(text.charset, "utf-8");
  assert.match(text["header:Content-Type"], /format=flowed/);
  assert.equal(attachment.name, "fixture.bin");
  assert.equal(attachment["header:Content-Description:asText"], "Liite ää");
  assert.deepEqual(attachment["header:X-Part-Trace:all"], draftHeaderTrace);
  assert.ok(!record.bodyStructure["header:Content-Type"].includes("caller-boundary"));
  console.log("Verified exact message and MIME part headers from IMAP");
}
if (forwardAttachment) {
  const [part] = message.attachments;
  assert.equal(part.type, embeddedType);
  assert.equal(part.name, "forwarded.eml");
  assert.equal(part.size, Buffer.byteLength(embeddedSource));
  const download = session.downloadUrl.replace("{accountId}", accountId).replace("{blobId}", part.blobId)
    .replace("{name}", "forwarded.eml").replace("{type}", encodeURIComponent(embeddedType));
  const response = await request(download);
  assert.equal(response.status, 200);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new TextEncoder().encode(embeddedSource));
  const parsed = await call([["Email/parse", { accountId, blobIds: [part.blobId], properties: ["subject"] }, "parse-inner"]]);
  assert.equal(result(parsed, "parse-inner", "Email/parse").parsed[part.blobId].subject, embeddedSubject);
  console.log("Verified byte-identical forwarding of a stored IMAP message and parsing of the attached blob");
}
if (destroySubmission) {
  const observed = await call([
    ["EmailSubmission/get", { accountId, ids: [submitted] }, "state"],
    ["EmailSubmission/query", { accountId }, "query"],
  ]);
  const sinceState = result(observed, "state", "EmailSubmission/get").state;
  const sinceQueryState = result(observed, "query", "EmailSubmission/query").queryState;
  const deletion = await call([
    ["EmailSubmission/set", {
      accountId, ifInState: sinceState, destroy: [submitted],
      onSuccessUpdateEmail: { [submitted]: { "keywords/$flagged": true } },
    }, "delete"],
    ["EmailSubmission/get", { accountId, ids: [submitted] }, "missing"],
    ["EmailSubmission/changes", { accountId, sinceState }, "changes"],
    ["EmailSubmission/queryChanges", { accountId, sinceQueryState }, "queryChanges"],
    ["Email/get", { accountId, ids: [emailId], fetchTextBodyValues: true }, "source"],
  ]);
  assert.deepEqual(result(deletion, "delete", "EmailSubmission/set").destroyed, [submitted]);
  assert.equal(deletion[1][0], "Email/set");
  assert.equal(deletion[1][2], "delete");
  assert.ok(Object.hasOwn(deletion[1][1].updated, emailId));
  assert.deepEqual(result(deletion, "missing", "EmailSubmission/get").notFound, [submitted]);
  assert.deepEqual(result(deletion, "changes", "EmailSubmission/changes").destroyed, [submitted]);
  assert.deepEqual(result(deletion, "queryChanges", "EmailSubmission/queryChanges").removed, [submitted]);
  const source = result(deletion, "source", "Email/get").list[0];
  assert.equal(source.keywords.$flagged, true);
  checkMessage(source);
  assert.equal((await replay()).notCreated?.retry?.type, "forbiddenToSend");
  console.log("Verified submission history removal, implicit IMAP update and replay protection");
}
for (const seen of [true, null]) {
  const changed = await call([
    ["Email/set", { accountId, update: { [emailId]: { "keywords/$seen": seen } } }, "set"],
    ["Email/get", { accountId, ids: [emailId] }, "read"],
  ]);
  assert.ok(Object.hasOwn(result(changed, "set", "Email/set").updated, emailId));
  assert.equal(Boolean(result(changed, "read", "Email/get").list[0].keywords.$seen), seen === true);
}
if (emulator) {
  const captured = await call([find(inbox), read]);
  checkMessage(result(captured, "read", "Email/get").list.find(({ subject }) => subject === marker));
}
console.log(`Accepted ${marker}`);
