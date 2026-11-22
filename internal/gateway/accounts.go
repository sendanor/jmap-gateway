package gateway

import "errors"

// Six accounts with maximum-length IDs and all state types fit in a single
// encrypted Web Push notification.
const maxAdditionalAccounts = 5

func New(config Config) (*Gateway, error) {
	if len(config.AdditionalAccounts) > maxAdditionalAccounts {
		return nil, errors.New("too many additional accounts")
	}
	seen := map[string]bool{config.AccountID: true}
	for _, account := range config.AdditionalAccounts {
		if seen[account.AccountID] {
			return nil, errors.New("account IDs must be distinct")
		}
		seen[account.AccountID] = true
	}
	g, err := newAccount(config)
	if err != nil {
		return nil, err
	}
	g.accounts = make(map[string]*Gateway, len(config.AdditionalAccounts))
	for _, account := range config.AdditionalAccounts {
		accountConfig := Config{
			Listen: config.Listen, PublicOrigin: config.PublicOrigin, TLSCert: config.TLSCert, TLSKey: config.TLSKey,
			Token: config.Token, AccountID: account.AccountID, StateDir: account.StateDir,
			IdentityName: account.IdentityName, IdentityEmail: account.IdentityEmail, DraftsMailbox: account.DraftsMailbox,
			IdentityAliases: account.IdentityAliases, MailboxMetadataVendor: account.MailboxMetadataVendor,
			IMAP: account.IMAP, SMTP: account.SMTP, ManageSieve: account.ManageSieve, CalDAV: account.CalDAV,
		}
		child, err := newAccount(accountConfig)
		if err != nil {
			_ = g.Close()
			return nil, err
		}
		// A batch can touch multiple accounts in order under one admission lock.
		child.gate, child.admitted = g.gate, g.admitted
		g.accounts[account.AccountID] = child
		g.session["accounts"].(object)[account.AccountID] = child.session["accounts"].(object)[account.AccountID]
		for capability := range child.session["primaryAccounts"].(object) {
			primary := g.session["primaryAccounts"].(object)
			if _, exists := primary[capability]; !exists {
				g.enableAccountCapability(account.AccountID, capability)
			}
		}
	}
	g.config.AdditionalAccounts = nil
	g.sessionState = digest(g.session)
	g.session["state"] = g.sessionState
	if err := g.openPush(); err != nil {
		_ = g.Close()
		return nil, err
	}
	return g, nil
}

func (g *Gateway) enableAccountCapability(account, capability string) {
	g.session["capabilities"].(object)[capability] = object{}
	g.session["accounts"].(object)[account].(object)["accountCapabilities"].(object)[capability] = object{}
	g.session["primaryAccounts"].(object)[capability] = account
}

func (g *Gateway) account(id string) *Gateway {
	if id == g.config.AccountID {
		return g
	}
	return g.accounts[id]
}

func (op *operation) requestOperation() *operation {
	if op.parent != nil {
		return op.parent
	}
	return op
}

func (op *operation) forAccount(id string) *operation {
	root := op.requestOperation()
	if root.g.config.AccountID == id {
		return root
	}
	if peer := root.peers[id]; peer != nil {
		return peer
	}
	account := root.g.account(id)
	if account == nil {
		return nil
	}
	if root.peers == nil {
		root.peers = make(map[string]*operation)
	}
	peer := &operation{g: account, ctx: root.ctx, created: root.created, parent: root}
	root.peers[id] = peer
	return peer
}

func (op *operation) closeConnections() {
	if op.closeIMAP != nil {
		op.closeIMAP()
	}
	for _, peer := range op.peers {
		peer.closeConnections()
	}
}
