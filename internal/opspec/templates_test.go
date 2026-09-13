package opspec

import "testing"

// Every operation the wizard may order in bulk has a template, and every
// template passes the same validation as an order typed by hand. A template
// the server would refuse would send the operator to the API documentation
// for a shape the panel was supposed to know.
func TestEveryCampaignReadyActionHasAValidTemplate(t *testing.T) {
	for _, action := range AllActions() {
		if CampaignExclusionReason(action) != "" || !ExecutableMode(action) {
			continue
		}
		payload, ok := PayloadTemplate(action)
		if !ok {
			t.Errorf("%s is ready for a campaign but has no template", action)
			continue
		}
		// The campaign validation is the one a bulk order goes through: a
		// per-host plan supplies the plan hash later.
		err := ValidateCampaignRequest(action, payload)
		if TemplateNeedsMaterial(action) {
			if err == nil {
				t.Errorf("the template of %s passes with placeholder material", action)
			}
			continue
		}
		if err != nil {
			t.Errorf("the template of %s does not validate: %v", action, err)
		}
	}
}
