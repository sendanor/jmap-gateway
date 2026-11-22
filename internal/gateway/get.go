package gateway

import "strings"

func validGetArgumentNames(raw rawObject, kind string) bool {
	for name, value := range raw {
		switch name {
		case "ids", "properties":
		case "accountId":
			if kind == "PushSubscription" {
				return false
			}
		case "bodyProperties", "fetchTextBodyValues", "fetchHTMLBodyValues", "fetchAllBodyValues", "maxBodyValueBytes":
			if kind != "Email" || string(value) == "null" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validateGetIDs(ids []string) string {
	if len(ids) > maxGet {
		return "requestTooLarge"
	}
	for _, id := range ids {
		if !jmapID.MatchString(strings.TrimPrefix(id, "#")) {
			return "invalidArguments"
		}
	}
	return ""
}

type getID struct {
	requested, resolved string
}

func (op *operation) uniqueGetIDs(ids []string) []getID {
	result := make([]getID, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		resolved := op.resolveID(id)
		key := resolved
		if key == "" {
			key = id
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, getID{requested: id, resolved: resolved})
	}
	return result
}

func validRecordProperties(properties []string, record object) bool {
	for _, property := range properties {
		if _, ok := record[property]; !ok {
			return false
		}
	}
	return true
}

func validGetProperties(kind string, args *getArgs) bool {
	switch kind {
	case "Email":
		for _, property := range args.Properties {
			if !contains(defaultEmailProperties, property) && property != "headers" && property != "bodyStructure" &&
				!strings.HasPrefix(property, "header:") {
				return false
			}
		}
		for _, property := range args.BodyProperties {
			if !contains(defaultBodyProperties, property) && property != "headers" && property != "subParts" &&
				!strings.HasPrefix(property, "header:") {
				return false
			}
		}
		return args.prepareHeaderProjections()
	case "Mailbox":
		return validRecordProperties(args.Properties, mailboxRecord(&box{}))
	case "Thread":
		return validRecordProperties(args.Properties, object{"id": nil, "emailIds": nil})
	case "EmailSubmission":
		return validRecordProperties(args.Properties, submissionObject(submissionRecord{}))
	case "Identity":
		return validRecordProperties(args.Properties, (identityProfile{}).record(identityID, ""))
	default: // Calendar preview
		return validRecordProperties(args.Properties, object{
			"id": nil, "name": nil, "description": nil, "color": nil, "sortOrder": nil, "isVisible": nil,
		})
	}
}
