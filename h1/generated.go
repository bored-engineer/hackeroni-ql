package h1

import (
	"encoding/json"
)

// Root entity of the Hackerone Schema
type Query struct {
	Application            *Application               `json:"application,omitempty"`
	BankTransferReference  *BankTransferReference     `json:"bank_transfer_reference,omitempty"`
	Clusters               *ClusterConnection         `json:"clusters,omitempty"`
	EmbeddedSubmissionForm *EmbeddedSubmissionForm    `json:"embedded_submission_form,omitempty"`
	ExternalProgram        *ExternalProgram           `json:"external_program,omitempty"`
	ExternalPrograms       *ExternalProgramConnection `json:"external_programs,omitempty"`
	GlobalFeatures         []*Feature                 `json:"global_features,omitempty"`
	HacktivityItems        *HacktivityItemConnection  `json:"hacktivity_items,omitempty"`
	ID                     *string                    `json:"id,omitempty"`
	Me                     *User                      `json:"me,omitempty"`
	// Fetches an object given its ID.
	Node             *Node             `json:"node,omitempty"`
	OauthApplication *OauthApplication `json:"oauth_application,omitempty"`
	Query            *Query            `json:"query,omitempty"`
	// DEPRECATED: Query for a Report node at the root level is not recommended.
	Report           *Report            `json:"report,omitempty"`
	ReportRetestUser *ReportRetestUser  `json:"report_retest_user,omitempty"`
	Reports          *ReportConnection  `json:"reports,omitempty"`
	Resource         *ResourceInterface `json:"resource,omitempty"`
	// DEPRECATED: This field is deprecated. This is consumed by HackerOne's legacy frontend.
	Session            *Session             `json:"session,omitempty"`
	SeverityCalculator *SeverityCalculator  `json:"severity_calculator,omitempty"`
	SLAStatuses        *SLAStatusConnection `json:"sla_statuses,omitempty"`
	Surveys            *SurveyConnection    `json:"surveys,omitempty"`
	Tasks              *TaskConnection      `json:"tasks,omitempty"`
	// DEPRECATED: Query for a Team node at the root level is not recommended. Ref T12456
	Team  *Team           `json:"team,omitempty"`
	Teams *TeamConnection `json:"teams,omitempty"`
	// DEPRECATED: Query for a User node at the root level is not recommended. Ref T12456
	User  *User           `json:"user,omitempty"`
	Users *UserConnection `json:"users,omitempty"`
}

// An object with an ID.
type Node struct {
	// ID of the object.
	ID                                            *string                                        `json:"id,omitempty"`
	TypeName__                                    string                                         `json:"__typename,omitempty"`
	ActivitiesAgreedOnGoingPublic                 *ActivitiesAgreedOnGoingPublic                 `json:"-"`
	ActivitiesBountyAwarded                       *ActivitiesBountyAwarded                       `json:"-"`
	ActivitiesBountySuggested                     *ActivitiesBountySuggested                     `json:"-"`
	ActivitiesBugCloned                           *ActivitiesBugCloned                           `json:"-"`
	ActivitiesBugDuplicate                        *ActivitiesBugDuplicate                        `json:"-"`
	ActivitiesBugFiled                            *ActivitiesBugFiled                            `json:"-"`
	ActivitiesBugInactive                         *ActivitiesBugInactive                         `json:"-"`
	ActivitiesBugInformative                      *ActivitiesBugInformative                      `json:"-"`
	ActivitiesBugNeedsMoreInfo                    *ActivitiesBugNeedsMoreInfo                    `json:"-"`
	ActivitiesBugNew                              *ActivitiesBugNew                              `json:"-"`
	ActivitiesBugNotApplicable                    *ActivitiesBugNotApplicable                    `json:"-"`
	ActivitiesBugReopened                         *ActivitiesBugReopened                         `json:"-"`
	ActivitiesBugResolved                         *ActivitiesBugResolved                         `json:"-"`
	ActivitiesBugSpam                             *ActivitiesBugSpam                             `json:"-"`
	ActivitiesBugTriaged                          *ActivitiesBugTriaged                          `json:"-"`
	ActivitiesCancelledDisclosureRequest          *ActivitiesCancelledDisclosureRequest          `json:"-"`
	ActivitiesChangedScope                        *ActivitiesChangedScope                        `json:"-"`
	ActivitiesComment                             *ActivitiesComment                             `json:"-"`
	ActivitiesCommentsClosed                      *ActivitiesCommentsClosed                      `json:"-"`
	ActivitiesCVEIDAdded                          *ActivitiesCVEIDAdded                          `json:"-"`
	ActivitiesExternalAdvisoryAdded               *ActivitiesExternalAdvisoryAdded               `json:"-"`
	ActivitiesExternalUserInvitationCancelled     *ActivitiesExternalUserInvitationCancelled     `json:"-"`
	ActivitiesExternalUserInvited                 *ActivitiesExternalUserInvited                 `json:"-"`
	ActivitiesExternalUserJoined                  *ActivitiesExternalUserJoined                  `json:"-"`
	ActivitiesExternalUserRemoved                 *ActivitiesExternalUserRemoved                 `json:"-"`
	ActivitiesGroupAssignedToBug                  *ActivitiesGroupAssignedToBug                  `json:"-"`
	ActivitiesHackerRequestedMediation            *ActivitiesHackerRequestedMediation            `json:"-"`
	ActivitiesManuallyDisclosed                   *ActivitiesManuallyDisclosed                   `json:"-"`
	ActivitiesMediationRequested                  *ActivitiesMediationRequested                  `json:"-"`
	ActivitiesNobodyAssignedToBug                 *ActivitiesNobodyAssignedToBug                 `json:"-"`
	ActivitiesNotEligibleForBounty                *ActivitiesNotEligibleForBounty                `json:"-"`
	ActivitiesProgramInactive                     *ActivitiesProgramInactive                     `json:"-"`
	ActivitiesReassignedToTeam                    *ActivitiesReassignedToTeam                    `json:"-"`
	ActivitiesReferenceIDAdded                    *ActivitiesReferenceIDAdded                    `json:"-"`
	ActivitiesReportBecamePublic                  *ActivitiesReportBecamePublic                  `json:"-"`
	ActivitiesReportCollaboratorInvited           *ActivitiesReportCollaboratorInvited           `json:"-"`
	ActivitiesReportCollaboratorJoined            *ActivitiesReportCollaboratorJoined            `json:"-"`
	ActivitiesReportSeverityUpdated               *ActivitiesReportSeverityUpdated               `json:"-"`
	ActivitiesReportTitleUpdated                  *ActivitiesReportTitleUpdated                  `json:"-"`
	ActivitiesReportVulnerabilityTypesUpdated     *ActivitiesReportVulnerabilityTypesUpdated     `json:"-"`
	ActivitiesSwagAwarded                         *ActivitiesSwagAwarded                         `json:"-"`
	ActivitiesTeamPublished                       *ActivitiesTeamPublished                       `json:"-"`
	ActivitiesUserAssignedToBug                   *ActivitiesUserAssignedToBug                   `json:"-"`
	ActivitiesUserBannedFromProgram               *ActivitiesUserBannedFromProgram               `json:"-"`
	ActivitiesUserCompletedRetest                 *ActivitiesUserCompletedRetest                 `json:"-"`
	ActivitiesUserJoined                          *ActivitiesUserJoined                          `json:"-"`
	Address                                       *Address                                       `json:"-"`
	Application                                   *Application                                   `json:"-"`
	Attachment                                    *Attachment                                    `json:"-"`
	Badge                                         *Badge                                         `json:"-"`
	BadgesUsers                                   *BadgesUsers                                   `json:"-"`
	BankTransferReference                         *BankTransferReference                         `json:"-"`
	BeneficiaryRequiredDetail                     *BeneficiaryRequiredDetail                     `json:"-"`
	BeneficiaryRequiredDetails                    *BeneficiaryRequiredDetails                    `json:"-"`
	BeneficiaryRequiredField                      *BeneficiaryRequiredField                      `json:"-"`
	Bounty                                        *Bounty                                        `json:"-"`
	BountyTable                                   *BountyTable                                   `json:"-"`
	BountyTableRow                                *BountyTableRow                                `json:"-"`
	ChallengeSetting                              *ChallengeSetting                              `json:"-"`
	Cluster                                       *Cluster                                       `json:"-"`
	CoinbasePayoutPreferenceType                  *CoinbasePayoutPreferenceType                  `json:"-"`
	CommonResponse                                *CommonResponse                                `json:"-"`
	Country                                       *Country                                       `json:"-"`
	Credential                                    *Credential                                    `json:"-"`
	Currency                                      *Currency                                      `json:"-"`
	CurrencycloudBankTransferPayoutPreferenceType *CurrencycloudBankTransferPayoutPreferenceType `json:"-"`
	CVERequest                                    *CVERequest                                    `json:"-"`
	Disclosed                                     *Disclosed                                     `json:"-"`
	EmbeddedSubmissionForm                        *EmbeddedSubmissionForm                        `json:"-"`
	Error                                         *Error                                         `json:"-"`
	Expression                                    *Expression                                    `json:"-"`
	ExternalProgram                               *ExternalProgram                               `json:"-"`
	Feature                                       *Feature                                       `json:"-"`
	HackerInvitationsProfile                      *HackerInvitationsProfile                      `json:"-"`
	HackerPublished                               *HackerPublished                               `json:"-"`
	HackeronePayrollPayoutPreferenceType          *HackeronePayrollPayoutPreferenceType          `json:"-"`
	HackeroneToJiraEventsConfiguration            *HackeroneToJiraEventsConfiguration            `json:"-"`
	InvitationQueue                               *InvitationQueue                               `json:"-"`
	InvitationsRetest                             *InvitationsRetest                             `json:"-"`
	InvitationsSoftLaunch                         *InvitationsSoftLaunch                         `json:"-"`
	JiraIntegration                               *JiraIntegration                               `json:"-"`
	JiraOauth                                     *JiraOauth                                     `json:"-"`
	JiraPriorityToSeverityRating                  *JiraPriorityToSeverityRating                  `json:"-"`
	JiraWebhook                                   *JiraWebhook                                   `json:"-"`
	LufthansaAccount                              *LufthansaAccount                              `json:"-"`
	NewFeatureNotification                        *NewFeatureNotification                        `json:"-"`
	PaypalPayoutPreferenceType                    *PaypalPayoutPreferenceType                    `json:"-"`
	PhabricatorIntegration                        *PhabricatorIntegration                        `json:"-"`
	ProfileMetricsSnapshot                        *ProfileMetricsSnapshot                        `json:"-"`
	ProgramHealthAcknowledgement                  *ProgramHealthAcknowledgement                  `json:"-"`
	ProgramStatistic                              *ProgramStatistic                              `json:"-"`
	Query                                         *Query                                         `json:"-"`
	Report                                        *Report                                        `json:"-"`
	ReportsCountPerScope                          *ReportsCountPerScope                          `json:"-"`
	ReportsCountPerWeakness                       *ReportsCountPerWeakness                       `json:"-"`
	Session                                       *Session                                       `json:"-"`
	Severity                                      *Severity                                      `json:"-"`
	SeverityCalculator                            *SeverityCalculator                            `json:"-"`
	SLASnapshot                                   *SLASnapshot                                   `json:"-"`
	SLAStatus                                     *SLAStatus                                     `json:"-"`
	SlackChannel                                  *SlackChannel                                  `json:"-"`
	SlackIntegration                              *SlackIntegration                              `json:"-"`
	SlackPipeline                                 *SlackPipeline                                 `json:"-"`
	SlackUser                                     *SlackUser                                     `json:"-"`
	StaticParticipant                             *StaticParticipant                             `json:"-"`
	StructuredPolicy                              *StructuredPolicy                              `json:"-"`
	StructuredScope                               *StructuredScope                               `json:"-"`
	StructuredScopeVersion                        *StructuredScopeVersion                        `json:"-"`
	SubmissionRequirements                        *SubmissionRequirements                        `json:"-"`
	Summary                                       *Summary                                       `json:"-"`
	Survey                                        *Survey                                        `json:"-"`
	SurveyAnswer                                  *SurveyAnswer                                  `json:"-"`
	SurveyStructuredResponse                      *SurveyStructuredResponse                      `json:"-"`
	Swag                                          *Swag                                          `json:"-"`
	Task                                          *Task                                          `json:"-"`
	TaxForm                                       *TaxForm                                       `json:"-"`
	Team                                          *Team                                          `json:"-"`
	TeamInboxView                                 *TeamInboxView                                 `json:"-"`
	TeamMember                                    *TeamMember                                    `json:"-"`
	TeamMemberGroup                               *TeamMemberGroup                               `json:"-"`
	TeamWeakness                                  *TeamWeakness                                  `json:"-"`
	TriageMeta                                    *TriageMeta                                    `json:"-"`
	Trigger                                       *Trigger                                       `json:"-"`
	TriggerActionLog                              *TriggerActionLog                              `json:"-"`
	TwoFactorAuthenticationCredentials            *TwoFactorAuthenticationCredentials            `json:"-"`
	Undisclosed                                   *Undisclosed                                   `json:"-"`
	User                                          *User                                          `json:"-"`
	UserSession                                   *UserSession                                   `json:"-"`
	UserSessionCountry                            *UserSessionCountry                            `json:"-"`
	Vote                                          *Vote                                          `json:"-"`
	VpnCredential                                 *VpnCredential                                 `json:"-"`
	VpnInstance                                   *VpnInstance                                   `json:"-"`
	Weakness                                      *Weakness                                      `json:"-"`
}

func (u *Node) UnmarshalJSON(data []byte) (err error) {
	type tmpType Node
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "ActivitiesAgreedOnGoingPublic":
		u.ActivitiesAgreedOnGoingPublic = &ActivitiesAgreedOnGoingPublic{}
		payload = u.ActivitiesAgreedOnGoingPublic
	case "ActivitiesBountyAwarded":
		u.ActivitiesBountyAwarded = &ActivitiesBountyAwarded{}
		payload = u.ActivitiesBountyAwarded
	case "ActivitiesBountySuggested":
		u.ActivitiesBountySuggested = &ActivitiesBountySuggested{}
		payload = u.ActivitiesBountySuggested
	case "ActivitiesBugCloned":
		u.ActivitiesBugCloned = &ActivitiesBugCloned{}
		payload = u.ActivitiesBugCloned
	case "ActivitiesBugDuplicate":
		u.ActivitiesBugDuplicate = &ActivitiesBugDuplicate{}
		payload = u.ActivitiesBugDuplicate
	case "ActivitiesBugFiled":
		u.ActivitiesBugFiled = &ActivitiesBugFiled{}
		payload = u.ActivitiesBugFiled
	case "ActivitiesBugInactive":
		u.ActivitiesBugInactive = &ActivitiesBugInactive{}
		payload = u.ActivitiesBugInactive
	case "ActivitiesBugInformative":
		u.ActivitiesBugInformative = &ActivitiesBugInformative{}
		payload = u.ActivitiesBugInformative
	case "ActivitiesBugNeedsMoreInfo":
		u.ActivitiesBugNeedsMoreInfo = &ActivitiesBugNeedsMoreInfo{}
		payload = u.ActivitiesBugNeedsMoreInfo
	case "ActivitiesBugNew":
		u.ActivitiesBugNew = &ActivitiesBugNew{}
		payload = u.ActivitiesBugNew
	case "ActivitiesBugNotApplicable":
		u.ActivitiesBugNotApplicable = &ActivitiesBugNotApplicable{}
		payload = u.ActivitiesBugNotApplicable
	case "ActivitiesBugReopened":
		u.ActivitiesBugReopened = &ActivitiesBugReopened{}
		payload = u.ActivitiesBugReopened
	case "ActivitiesBugResolved":
		u.ActivitiesBugResolved = &ActivitiesBugResolved{}
		payload = u.ActivitiesBugResolved
	case "ActivitiesBugSpam":
		u.ActivitiesBugSpam = &ActivitiesBugSpam{}
		payload = u.ActivitiesBugSpam
	case "ActivitiesBugTriaged":
		u.ActivitiesBugTriaged = &ActivitiesBugTriaged{}
		payload = u.ActivitiesBugTriaged
	case "ActivitiesCancelledDisclosureRequest":
		u.ActivitiesCancelledDisclosureRequest = &ActivitiesCancelledDisclosureRequest{}
		payload = u.ActivitiesCancelledDisclosureRequest
	case "ActivitiesChangedScope":
		u.ActivitiesChangedScope = &ActivitiesChangedScope{}
		payload = u.ActivitiesChangedScope
	case "ActivitiesComment":
		u.ActivitiesComment = &ActivitiesComment{}
		payload = u.ActivitiesComment
	case "ActivitiesCommentsClosed":
		u.ActivitiesCommentsClosed = &ActivitiesCommentsClosed{}
		payload = u.ActivitiesCommentsClosed
	case "ActivitiesCVEIDAdded":
		u.ActivitiesCVEIDAdded = &ActivitiesCVEIDAdded{}
		payload = u.ActivitiesCVEIDAdded
	case "ActivitiesExternalAdvisoryAdded":
		u.ActivitiesExternalAdvisoryAdded = &ActivitiesExternalAdvisoryAdded{}
		payload = u.ActivitiesExternalAdvisoryAdded
	case "ActivitiesExternalUserInvitationCancelled":
		u.ActivitiesExternalUserInvitationCancelled = &ActivitiesExternalUserInvitationCancelled{}
		payload = u.ActivitiesExternalUserInvitationCancelled
	case "ActivitiesExternalUserInvited":
		u.ActivitiesExternalUserInvited = &ActivitiesExternalUserInvited{}
		payload = u.ActivitiesExternalUserInvited
	case "ActivitiesExternalUserJoined":
		u.ActivitiesExternalUserJoined = &ActivitiesExternalUserJoined{}
		payload = u.ActivitiesExternalUserJoined
	case "ActivitiesExternalUserRemoved":
		u.ActivitiesExternalUserRemoved = &ActivitiesExternalUserRemoved{}
		payload = u.ActivitiesExternalUserRemoved
	case "ActivitiesGroupAssignedToBug":
		u.ActivitiesGroupAssignedToBug = &ActivitiesGroupAssignedToBug{}
		payload = u.ActivitiesGroupAssignedToBug
	case "ActivitiesHackerRequestedMediation":
		u.ActivitiesHackerRequestedMediation = &ActivitiesHackerRequestedMediation{}
		payload = u.ActivitiesHackerRequestedMediation
	case "ActivitiesManuallyDisclosed":
		u.ActivitiesManuallyDisclosed = &ActivitiesManuallyDisclosed{}
		payload = u.ActivitiesManuallyDisclosed
	case "ActivitiesMediationRequested":
		u.ActivitiesMediationRequested = &ActivitiesMediationRequested{}
		payload = u.ActivitiesMediationRequested
	case "ActivitiesNobodyAssignedToBug":
		u.ActivitiesNobodyAssignedToBug = &ActivitiesNobodyAssignedToBug{}
		payload = u.ActivitiesNobodyAssignedToBug
	case "ActivitiesNotEligibleForBounty":
		u.ActivitiesNotEligibleForBounty = &ActivitiesNotEligibleForBounty{}
		payload = u.ActivitiesNotEligibleForBounty
	case "ActivitiesProgramInactive":
		u.ActivitiesProgramInactive = &ActivitiesProgramInactive{}
		payload = u.ActivitiesProgramInactive
	case "ActivitiesReassignedToTeam":
		u.ActivitiesReassignedToTeam = &ActivitiesReassignedToTeam{}
		payload = u.ActivitiesReassignedToTeam
	case "ActivitiesReferenceIDAdded":
		u.ActivitiesReferenceIDAdded = &ActivitiesReferenceIDAdded{}
		payload = u.ActivitiesReferenceIDAdded
	case "ActivitiesReportBecamePublic":
		u.ActivitiesReportBecamePublic = &ActivitiesReportBecamePublic{}
		payload = u.ActivitiesReportBecamePublic
	case "ActivitiesReportCollaboratorInvited":
		u.ActivitiesReportCollaboratorInvited = &ActivitiesReportCollaboratorInvited{}
		payload = u.ActivitiesReportCollaboratorInvited
	case "ActivitiesReportCollaboratorJoined":
		u.ActivitiesReportCollaboratorJoined = &ActivitiesReportCollaboratorJoined{}
		payload = u.ActivitiesReportCollaboratorJoined
	case "ActivitiesReportSeverityUpdated":
		u.ActivitiesReportSeverityUpdated = &ActivitiesReportSeverityUpdated{}
		payload = u.ActivitiesReportSeverityUpdated
	case "ActivitiesReportTitleUpdated":
		u.ActivitiesReportTitleUpdated = &ActivitiesReportTitleUpdated{}
		payload = u.ActivitiesReportTitleUpdated
	case "ActivitiesReportVulnerabilityTypesUpdated":
		u.ActivitiesReportVulnerabilityTypesUpdated = &ActivitiesReportVulnerabilityTypesUpdated{}
		payload = u.ActivitiesReportVulnerabilityTypesUpdated
	case "ActivitiesSwagAwarded":
		u.ActivitiesSwagAwarded = &ActivitiesSwagAwarded{}
		payload = u.ActivitiesSwagAwarded
	case "ActivitiesTeamPublished":
		u.ActivitiesTeamPublished = &ActivitiesTeamPublished{}
		payload = u.ActivitiesTeamPublished
	case "ActivitiesUserAssignedToBug":
		u.ActivitiesUserAssignedToBug = &ActivitiesUserAssignedToBug{}
		payload = u.ActivitiesUserAssignedToBug
	case "ActivitiesUserBannedFromProgram":
		u.ActivitiesUserBannedFromProgram = &ActivitiesUserBannedFromProgram{}
		payload = u.ActivitiesUserBannedFromProgram
	case "ActivitiesUserCompletedRetest":
		u.ActivitiesUserCompletedRetest = &ActivitiesUserCompletedRetest{}
		payload = u.ActivitiesUserCompletedRetest
	case "ActivitiesUserJoined":
		u.ActivitiesUserJoined = &ActivitiesUserJoined{}
		payload = u.ActivitiesUserJoined
	case "Address":
		u.Address = &Address{}
		payload = u.Address
	case "Application":
		u.Application = &Application{}
		payload = u.Application
	case "Attachment":
		u.Attachment = &Attachment{}
		payload = u.Attachment
	case "Badge":
		u.Badge = &Badge{}
		payload = u.Badge
	case "BadgesUsers":
		u.BadgesUsers = &BadgesUsers{}
		payload = u.BadgesUsers
	case "BankTransferReference":
		u.BankTransferReference = &BankTransferReference{}
		payload = u.BankTransferReference
	case "BeneficiaryRequiredDetail":
		u.BeneficiaryRequiredDetail = &BeneficiaryRequiredDetail{}
		payload = u.BeneficiaryRequiredDetail
	case "BeneficiaryRequiredDetails":
		u.BeneficiaryRequiredDetails = &BeneficiaryRequiredDetails{}
		payload = u.BeneficiaryRequiredDetails
	case "BeneficiaryRequiredField":
		u.BeneficiaryRequiredField = &BeneficiaryRequiredField{}
		payload = u.BeneficiaryRequiredField
	case "Bounty":
		u.Bounty = &Bounty{}
		payload = u.Bounty
	case "BountyTable":
		u.BountyTable = &BountyTable{}
		payload = u.BountyTable
	case "BountyTableRow":
		u.BountyTableRow = &BountyTableRow{}
		payload = u.BountyTableRow
	case "ChallengeSetting":
		u.ChallengeSetting = &ChallengeSetting{}
		payload = u.ChallengeSetting
	case "Cluster":
		u.Cluster = &Cluster{}
		payload = u.Cluster
	case "CoinbasePayoutPreferenceType":
		u.CoinbasePayoutPreferenceType = &CoinbasePayoutPreferenceType{}
		payload = u.CoinbasePayoutPreferenceType
	case "CommonResponse":
		u.CommonResponse = &CommonResponse{}
		payload = u.CommonResponse
	case "Country":
		u.Country = &Country{}
		payload = u.Country
	case "Credential":
		u.Credential = &Credential{}
		payload = u.Credential
	case "Currency":
		u.Currency = &Currency{}
		payload = u.Currency
	case "CurrencycloudBankTransferPayoutPreferenceType":
		u.CurrencycloudBankTransferPayoutPreferenceType = &CurrencycloudBankTransferPayoutPreferenceType{}
		payload = u.CurrencycloudBankTransferPayoutPreferenceType
	case "CVERequest":
		u.CVERequest = &CVERequest{}
		payload = u.CVERequest
	case "Disclosed":
		u.Disclosed = &Disclosed{}
		payload = u.Disclosed
	case "EmbeddedSubmissionForm":
		u.EmbeddedSubmissionForm = &EmbeddedSubmissionForm{}
		payload = u.EmbeddedSubmissionForm
	case "Error":
		u.Error = &Error{}
		payload = u.Error
	case "Expression":
		u.Expression = &Expression{}
		payload = u.Expression
	case "ExternalProgram":
		u.ExternalProgram = &ExternalProgram{}
		payload = u.ExternalProgram
	case "Feature":
		u.Feature = &Feature{}
		payload = u.Feature
	case "HackerInvitationsProfile":
		u.HackerInvitationsProfile = &HackerInvitationsProfile{}
		payload = u.HackerInvitationsProfile
	case "HackerPublished":
		u.HackerPublished = &HackerPublished{}
		payload = u.HackerPublished
	case "HackeronePayrollPayoutPreferenceType":
		u.HackeronePayrollPayoutPreferenceType = &HackeronePayrollPayoutPreferenceType{}
		payload = u.HackeronePayrollPayoutPreferenceType
	case "HackeroneToJiraEventsConfiguration":
		u.HackeroneToJiraEventsConfiguration = &HackeroneToJiraEventsConfiguration{}
		payload = u.HackeroneToJiraEventsConfiguration
	case "InvitationQueue":
		u.InvitationQueue = &InvitationQueue{}
		payload = u.InvitationQueue
	case "InvitationsRetest":
		u.InvitationsRetest = &InvitationsRetest{}
		payload = u.InvitationsRetest
	case "InvitationsSoftLaunch":
		u.InvitationsSoftLaunch = &InvitationsSoftLaunch{}
		payload = u.InvitationsSoftLaunch
	case "JiraIntegration":
		u.JiraIntegration = &JiraIntegration{}
		payload = u.JiraIntegration
	case "JiraOauth":
		u.JiraOauth = &JiraOauth{}
		payload = u.JiraOauth
	case "JiraPriorityToSeverityRating":
		u.JiraPriorityToSeverityRating = &JiraPriorityToSeverityRating{}
		payload = u.JiraPriorityToSeverityRating
	case "JiraWebhook":
		u.JiraWebhook = &JiraWebhook{}
		payload = u.JiraWebhook
	case "LufthansaAccount":
		u.LufthansaAccount = &LufthansaAccount{}
		payload = u.LufthansaAccount
	case "NewFeatureNotification":
		u.NewFeatureNotification = &NewFeatureNotification{}
		payload = u.NewFeatureNotification
	case "PaypalPayoutPreferenceType":
		u.PaypalPayoutPreferenceType = &PaypalPayoutPreferenceType{}
		payload = u.PaypalPayoutPreferenceType
	case "PhabricatorIntegration":
		u.PhabricatorIntegration = &PhabricatorIntegration{}
		payload = u.PhabricatorIntegration
	case "ProfileMetricsSnapshot":
		u.ProfileMetricsSnapshot = &ProfileMetricsSnapshot{}
		payload = u.ProfileMetricsSnapshot
	case "ProgramHealthAcknowledgement":
		u.ProgramHealthAcknowledgement = &ProgramHealthAcknowledgement{}
		payload = u.ProgramHealthAcknowledgement
	case "ProgramStatistic":
		u.ProgramStatistic = &ProgramStatistic{}
		payload = u.ProgramStatistic
	case "Query":
		u.Query = &Query{}
		payload = u.Query
	case "Report":
		u.Report = &Report{}
		payload = u.Report
	case "ReportsCountPerScope":
		u.ReportsCountPerScope = &ReportsCountPerScope{}
		payload = u.ReportsCountPerScope
	case "ReportsCountPerWeakness":
		u.ReportsCountPerWeakness = &ReportsCountPerWeakness{}
		payload = u.ReportsCountPerWeakness
	case "Session":
		u.Session = &Session{}
		payload = u.Session
	case "Severity":
		u.Severity = &Severity{}
		payload = u.Severity
	case "SeverityCalculator":
		u.SeverityCalculator = &SeverityCalculator{}
		payload = u.SeverityCalculator
	case "SLASnapshot":
		u.SLASnapshot = &SLASnapshot{}
		payload = u.SLASnapshot
	case "SLAStatus":
		u.SLAStatus = &SLAStatus{}
		payload = u.SLAStatus
	case "SlackChannel":
		u.SlackChannel = &SlackChannel{}
		payload = u.SlackChannel
	case "SlackIntegration":
		u.SlackIntegration = &SlackIntegration{}
		payload = u.SlackIntegration
	case "SlackPipeline":
		u.SlackPipeline = &SlackPipeline{}
		payload = u.SlackPipeline
	case "SlackUser":
		u.SlackUser = &SlackUser{}
		payload = u.SlackUser
	case "StaticParticipant":
		u.StaticParticipant = &StaticParticipant{}
		payload = u.StaticParticipant
	case "StructuredPolicy":
		u.StructuredPolicy = &StructuredPolicy{}
		payload = u.StructuredPolicy
	case "StructuredScope":
		u.StructuredScope = &StructuredScope{}
		payload = u.StructuredScope
	case "StructuredScopeVersion":
		u.StructuredScopeVersion = &StructuredScopeVersion{}
		payload = u.StructuredScopeVersion
	case "SubmissionRequirements":
		u.SubmissionRequirements = &SubmissionRequirements{}
		payload = u.SubmissionRequirements
	case "Summary":
		u.Summary = &Summary{}
		payload = u.Summary
	case "Survey":
		u.Survey = &Survey{}
		payload = u.Survey
	case "SurveyAnswer":
		u.SurveyAnswer = &SurveyAnswer{}
		payload = u.SurveyAnswer
	case "SurveyStructuredResponse":
		u.SurveyStructuredResponse = &SurveyStructuredResponse{}
		payload = u.SurveyStructuredResponse
	case "Swag":
		u.Swag = &Swag{}
		payload = u.Swag
	case "Task":
		u.Task = &Task{}
		payload = u.Task
	case "TaxForm":
		u.TaxForm = &TaxForm{}
		payload = u.TaxForm
	case "Team":
		u.Team = &Team{}
		payload = u.Team
	case "TeamInboxView":
		u.TeamInboxView = &TeamInboxView{}
		payload = u.TeamInboxView
	case "TeamMember":
		u.TeamMember = &TeamMember{}
		payload = u.TeamMember
	case "TeamMemberGroup":
		u.TeamMemberGroup = &TeamMemberGroup{}
		payload = u.TeamMemberGroup
	case "TeamWeakness":
		u.TeamWeakness = &TeamWeakness{}
		payload = u.TeamWeakness
	case "TriageMeta":
		u.TriageMeta = &TriageMeta{}
		payload = u.TriageMeta
	case "Trigger":
		u.Trigger = &Trigger{}
		payload = u.Trigger
	case "TriggerActionLog":
		u.TriggerActionLog = &TriggerActionLog{}
		payload = u.TriggerActionLog
	case "TwoFactorAuthenticationCredentials":
		u.TwoFactorAuthenticationCredentials = &TwoFactorAuthenticationCredentials{}
		payload = u.TwoFactorAuthenticationCredentials
	case "Undisclosed":
		u.Undisclosed = &Undisclosed{}
		payload = u.Undisclosed
	case "User":
		u.User = &User{}
		payload = u.User
	case "UserSession":
		u.UserSession = &UserSession{}
		payload = u.UserSession
	case "UserSessionCountry":
		u.UserSessionCountry = &UserSessionCountry{}
		payload = u.UserSessionCountry
	case "Vote":
		u.Vote = &Vote{}
		payload = u.Vote
	case "VpnCredential":
		u.VpnCredential = &VpnCredential{}
		payload = u.VpnCredential
	case "VpnInstance":
		u.VpnInstance = &VpnInstance{}
		payload = u.VpnInstance
	case "Weakness":
		u.Weakness = &Weakness{}
		payload = u.Weakness
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HackerOne session
type Session struct {
	CSRFToken *string `json:"csrf_token,omitempty"`
	ID        *string `json:"id,omitempty"`
}

// A HackerOne user
type User struct {
	ID_                                  *string                       `json:"_id,omitempty"`
	AccountRecoveryPhoneNumber           *string                       `json:"account_recovery_phone_number,omitempty"`
	AccountRecoveryPhoneNumberSentAt     *DateTime                     `json:"account_recovery_phone_number_sent_at,omitempty"`
	AccountRecoveryPhoneNumberVerifiedAt *DateTime                     `json:"account_recovery_phone_number_verified_at,omitempty"`
	AccountRecoveryUnverifiedPhoneNumber *string                       `json:"account_recovery_unverified_phone_number,omitempty"`
	Address                              *Address                      `json:"address,omitempty"`
	AncTriager                           *bool                         `json:"anc_triager,omitempty"`
	AuthenticationService                *AuthenticationServiceEnum    `json:"authentication_service,omitempty"`
	Badges                               *BadgesUsersConnection        `json:"badges,omitempty"`
	Bio                                  *string                       `json:"bio,omitempty"`
	BlacklistedFromHackerPublish         *bool                         `json:"blacklisted_from_hacker_publish,omitempty"`
	Bounties                             *BountyConnection             `json:"bounties,omitempty"`
	CalendarToken                        *string                       `json:"calendar_token,omitempty"`
	CreatedAt                            *DateTime                     `json:"created_at,omitempty"`
	DemoHacker                           *bool                         `json:"demo_hacker,omitempty"`
	Disabled                             *bool                         `json:"disabled,omitempty"`
	DuplicateUsers                       *UserConnection               `json:"duplicate_users,omitempty"`
	EditUnclaimedProfiles                *bool                         `json:"edit_unclaimed_profiles,omitempty"`
	Email                                *string                       `json:"email,omitempty"`
	FacebookUserID                       *string                       `json:"facebook_user_id,omitempty"`
	FacebookUserName                     *string                       `json:"facebook_user_name,omitempty"`
	FbAuthSupported                      *bool                         `json:"fb_auth_supported,omitempty"`
	Features                             []*Feature                    `json:"features,omitempty"`
	HackerInvitationsProfile             *HackerInvitationsProfile     `json:"hacker_invitations_profile,omitempty"`
	HackeroneTriager                     *bool                         `json:"hackerone_triager,omitempty"`
	ICanUpdateInvitationProfile          *bool                         `json:"i_can_update_invitation_profile,omitempty"`
	ICanUpdateUsername                   *bool                         `json:"i_can_update_username,omitempty"`
	ID                                   *string                       `json:"id,omitempty"`
	Impact                               *float64                      `json:"impact,omitempty"`
	ImpactPercentile                     *float64                      `json:"impact_percentile,omitempty"`
	InvitationPreference                 *InvitationPreferenceTypeEnum `json:"invitation_preference,omitempty"`
	InvitationQueues                     *InvitationQueueConnection    `json:"invitation_queues,omitempty"`
	Location                             *string                       `json:"location,omitempty"`
	LufthansaAccount                     *LufthansaAccount             `json:"lufthansa_account,omitempty"`
	MemberOfVerifiedTeam                 *bool                         `json:"member_of_verified_team,omitempty"`
	Membership                           *TeamMember                   `json:"membership,omitempty"`
	Memberships                          *TeamMemberConnection         `json:"memberships,omitempty"`
	Name                                 *string                       `json:"name,omitempty"`
	NewFeatureNotification               *NewFeatureNotification       `json:"new_feature_notification,omitempty"`
	NextUpdateUsernameDate               *string                       `json:"next_update_username_date,omitempty"`
	OTPBackupCodes                       []*string                     `json:"otp_backup_codes,omitempty"`
	PayoutPreferences                    []*PayoutPreferenceUnion      `json:"payout_preferences,omitempty"`
	ProfilePicture                       *string                       `json:"profile_picture,omitempty"`
	// DEPRECATED: Returns all the possible profile pictures instead of just the one you want use .profile_picture instead.
	ProfilePictures               *string                                 `json:"profile_pictures,omitempty"`
	ProgramHealthAcknowledgements *ProgramHealthAcknowledgementConnection `json:"program_health_acknowledgements,omitempty"`
	Rank                          *int32                                  `json:"rank,omitempty"`
	RemainingReports              *int32                                  `json:"remaining_reports,omitempty"`
	ReportRetestUsers             *ReportRetestUserConnection             `json:"report_retest_users,omitempty"`
	Reports                       *ReportConnection                       `json:"reports,omitempty"`
	Reputation                    *int32                                  `json:"reputation,omitempty"`
	SamlEnabled                   *bool                                   `json:"saml_enabled,omitempty"`
	Sessions                      *UserSessionConnection                  `json:"sessions,omitempty"`
	Signal                        *float64                                `json:"signal,omitempty"`
	SignalPercentile              *float64                                `json:"signal_percentile,omitempty"`
	SoftLaunchInvitations         *SoftLaunchConnection                   `json:"soft_launch_invitations,omitempty"`
	SubscribedForMonthlyDigest    *bool                                   `json:"subscribed_for_monthly_digest,omitempty"`
	SubscribedForTeamMessages     *bool                                   `json:"subscribed_for_team_messages,omitempty"`
	Swag                          *SwagConnection                         `json:"swag,omitempty"`
	TaxForm                       *TaxForm                                `json:"tax_form,omitempty"`
	Teams                         *TeamConnection                         `json:"teams,omitempty"`
	TOTPEnabled                   *bool                                   `json:"totp_enabled,omitempty"`
	TOTPSupported                 *bool                                   `json:"totp_supported,omitempty"`
	TriageUser                    *bool                                   `json:"triage_user,omitempty"`
	TshirtSize                    *TshirtSizeEnum                         `json:"tshirt_size,omitempty"`
	UnconfirmedEmail              *string                                 `json:"unconfirmed_email,omitempty"`
	URL                           *URI                                    `json:"url,omitempty"`
	UserType                      *string                                 `json:"user_type,omitempty"`
	Username                      *string                                 `json:"username,omitempty"`
	VpnCredentials                []*VpnCredential                        `json:"vpn_credentials,omitempty"`
	VpnInstances                  []*VpnInstance                          `json:"vpn_instances,omitempty"`
	Website                       *string                                 `json:"website,omitempty"`
	WhitelistedTeams              *WhitelistedTeamConnection              `json:"whitelisted_teams,omitempty"`
	YearInReviewPublishedAt       *DateTime                               `json:"year_in_review_published_at,omitempty"`
}

// Represents a type that can be retrieved by a URL.
type ResourceInterface struct {
	URL                    *URI                    `json:"url,omitempty"`
	TypeName__             string                  `json:"__typename,omitempty"`
	BountyTable            *BountyTable            `json:"-"`
	BountyTableRow         *BountyTableRow         `json:"-"`
	CVERequest             *CVERequest             `json:"-"`
	Report                 *Report                 `json:"-"`
	SlackPipeline          *SlackPipeline          `json:"-"`
	StructuredPolicy       *StructuredPolicy       `json:"-"`
	StructuredScope        *StructuredScope        `json:"-"`
	StructuredScopeVersion *StructuredScopeVersion `json:"-"`
	Survey                 *Survey                 `json:"-"`
	Task                   *Task                   `json:"-"`
	Team                   *Team                   `json:"-"`
	TriageMeta             *TriageMeta             `json:"-"`
	Trigger                *Trigger                `json:"-"`
	User                   *User                   `json:"-"`
}

func (u *ResourceInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType ResourceInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "BountyTable":
		u.BountyTable = &BountyTable{}
		payload = u.BountyTable
	case "BountyTableRow":
		u.BountyTableRow = &BountyTableRow{}
		payload = u.BountyTableRow
	case "CVERequest":
		u.CVERequest = &CVERequest{}
		payload = u.CVERequest
	case "Report":
		u.Report = &Report{}
		payload = u.Report
	case "SlackPipeline":
		u.SlackPipeline = &SlackPipeline{}
		payload = u.SlackPipeline
	case "StructuredPolicy":
		u.StructuredPolicy = &StructuredPolicy{}
		payload = u.StructuredPolicy
	case "StructuredScope":
		u.StructuredScope = &StructuredScope{}
		payload = u.StructuredScope
	case "StructuredScopeVersion":
		u.StructuredScopeVersion = &StructuredScopeVersion{}
		payload = u.StructuredScopeVersion
	case "Survey":
		u.Survey = &Survey{}
		payload = u.Survey
	case "Task":
		u.Task = &Task{}
		payload = u.Task
	case "Team":
		u.Team = &Team{}
		payload = u.Team
	case "TriageMeta":
		u.TriageMeta = &TriageMeta{}
		payload = u.TriageMeta
	case "Trigger":
		u.Trigger = &Trigger{}
		payload = u.Trigger
	case "User":
		u.User = &User{}
		payload = u.User
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HackerOne user's address used for submitting swag
type Address struct {
	ID_         *string   `json:"_id,omitempty"`
	City        *string   `json:"city,omitempty"`
	Country     *string   `json:"country,omitempty"`
	CreatedAt   *DateTime `json:"created_at,omitempty"`
	ID          *string   `json:"id,omitempty"`
	Name        *string   `json:"name,omitempty"`
	PhoneNumber *string   `json:"phone_number,omitempty"`
	PostalCode  *string   `json:"postal_code,omitempty"`
	State       *string   `json:"state,omitempty"`
	Street      *string   `json:"street,omitempty"`
	// DEPRECATED: Query tshirt size on User instead
	TshirtSize *TshirtSizeEnum `json:"tshirt_size,omitempty"`
}

// Tshirt size
type TshirtSizeEnum string

const (
	TshirtSizeEnumMSmall   TshirtSizeEnum = "M_Small"
	TshirtSizeEnumMMedium  TshirtSizeEnum = "M_Medium"
	TshirtSizeEnumMLarge   TshirtSizeEnum = "M_Large"
	TshirtSizeEnumMXLarge  TshirtSizeEnum = "M_XLarge"
	TshirtSizeEnumMXXLarge TshirtSizeEnum = "M_XXLarge"
	TshirtSizeEnumWSmall   TshirtSizeEnum = "W_Small"
	TshirtSizeEnumWMedium  TshirtSizeEnum = "W_Medium"
	TshirtSizeEnumWLarge   TshirtSizeEnum = "W_Large"
	TshirtSizeEnumWXLarge  TshirtSizeEnum = "W_XLarge"
	TshirtSizeEnumWXXLarge TshirtSizeEnum = "W_XXLarge"
)

// Settings for a user's Lufthansa Account
type LufthansaAccount struct {
	CreatedAt *DateTime `json:"created_at,omitempty"`
	FirstName *string   `json:"first_name,omitempty"`
	ID        *string   `json:"id,omitempty"`
	LastName  *string   `json:"last_name,omitempty"`
	Number    *string   `json:"number,omitempty"`
	UpdatedAt *DateTime `json:"updated_at,omitempty"`
}

// VPN Credential for a user
type VpnCredential struct {
	ID    *string `json:"id,omitempty"`
	Name  *string `json:"name,omitempty"`
	State *string `json:"state,omitempty"`
}

// VPN Instance for a user
type VpnInstance struct {
	ID    *string `json:"id,omitempty"`
	State *string `json:"state,omitempty"`
}

// A tax form for a user
type TaxForm struct {
	CreatedAt         *DateTime         `json:"created_at,omitempty"`
	HelloSignClientID *string           `json:"hello_sign_client_id,omitempty"`
	ID                *string           `json:"id,omitempty"`
	SignedAt          *DateTime         `json:"signed_at,omitempty"`
	Status            *TaxFormStateEnum `json:"status,omitempty"`
	Type              *TaxFormTypeEnum  `json:"type,omitempty"`
	URL               *string           `json:"url,omitempty"`
}

// Type of a tax form
type TaxFormTypeEnum string

const (
	TaxFormTypeEnumW9          TaxFormTypeEnum = "W9"
	TaxFormTypeEnumW9Corporate TaxFormTypeEnum = "W9Corporate"
	TaxFormTypeEnumW8BEN       TaxFormTypeEnum = "W8BEN"
	TaxFormTypeEnumW8BENE      TaxFormTypeEnum = "W8BENE"
)

// Status of a tax form
type TaxFormStateEnum string

const (
	TaxFormStateEnumRequested   TaxFormStateEnum = "requested"
	TaxFormStateEnumValid       TaxFormStateEnum = "valid"
	TaxFormStateEnumNeedsReview TaxFormStateEnum = "needs_review"
	TaxFormStateEnumRejected    TaxFormStateEnum = "rejected"
	TaxFormStateEnumExpired     TaxFormStateEnum = "expired"
	TaxFormStateEnumUnavailable TaxFormStateEnum = "unavailable"
)

// Different possible profile picture sizes
type ProfilePictureSizes string

const (
	// 62x62
	ProfilePictureSizesSmall ProfilePictureSizes = "small"
	// 82x82
	ProfilePictureSizesMedium ProfilePictureSizes = "medium"
	// 110x110
	ProfilePictureSizesLarge ProfilePictureSizes = "large"
	// 260x260
	ProfilePictureSizesXtralarge ProfilePictureSizes = "xtralarge"
)

// A user can have payout preferences for different payment services
type PayoutPreferenceUnion struct {
	TypeName__                                    string                                         `json:"__typename,omitempty"`
	CoinbasePayoutPreferenceType                  *CoinbasePayoutPreferenceType                  `json:"-"`
	CurrencycloudBankTransferPayoutPreferenceType *CurrencycloudBankTransferPayoutPreferenceType `json:"-"`
	PaypalPayoutPreferenceType                    *PaypalPayoutPreferenceType                    `json:"-"`
	HackeronePayrollPayoutPreferenceType          *HackeronePayrollPayoutPreferenceType          `json:"-"`
}

func (u *PayoutPreferenceUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType PayoutPreferenceUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "CoinbasePayoutPreferenceType":
		u.CoinbasePayoutPreferenceType = &CoinbasePayoutPreferenceType{}
		payload = u.CoinbasePayoutPreferenceType
	case "CurrencycloudBankTransferPayoutPreferenceType":
		u.CurrencycloudBankTransferPayoutPreferenceType = &CurrencycloudBankTransferPayoutPreferenceType{}
		payload = u.CurrencycloudBankTransferPayoutPreferenceType
	case "PaypalPayoutPreferenceType":
		u.PaypalPayoutPreferenceType = &PaypalPayoutPreferenceType{}
		payload = u.PaypalPayoutPreferenceType
	case "HackeronePayrollPayoutPreferenceType":
		u.HackeronePayrollPayoutPreferenceType = &HackeronePayrollPayoutPreferenceType{}
		payload = u.HackeronePayrollPayoutPreferenceType
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A Coinbase Payout Preference
type CoinbasePayoutPreferenceType struct {
	ID_     *string `json:"_id,omitempty"`
	Default *bool   `json:"default,omitempty"`
	Email   *string `json:"email,omitempty"`
	ID      *string `json:"id,omitempty"`
}

// A interface for the common fields on an Payout Preference
type PayoutPreferenceInterface struct {
	ID_                                           *string                                        `json:"_id,omitempty"`
	Default                                       *bool                                          `json:"default,omitempty"`
	ID                                            *string                                        `json:"id,omitempty"`
	TypeName__                                    string                                         `json:"__typename,omitempty"`
	CoinbasePayoutPreferenceType                  *CoinbasePayoutPreferenceType                  `json:"-"`
	CurrencycloudBankTransferPayoutPreferenceType *CurrencycloudBankTransferPayoutPreferenceType `json:"-"`
	HackeronePayrollPayoutPreferenceType          *HackeronePayrollPayoutPreferenceType          `json:"-"`
	PaypalPayoutPreferenceType                    *PaypalPayoutPreferenceType                    `json:"-"`
}

func (u *PayoutPreferenceInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType PayoutPreferenceInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "CoinbasePayoutPreferenceType":
		u.CoinbasePayoutPreferenceType = &CoinbasePayoutPreferenceType{}
		payload = u.CoinbasePayoutPreferenceType
	case "CurrencycloudBankTransferPayoutPreferenceType":
		u.CurrencycloudBankTransferPayoutPreferenceType = &CurrencycloudBankTransferPayoutPreferenceType{}
		payload = u.CurrencycloudBankTransferPayoutPreferenceType
	case "HackeronePayrollPayoutPreferenceType":
		u.HackeronePayrollPayoutPreferenceType = &HackeronePayrollPayoutPreferenceType{}
		payload = u.HackeronePayrollPayoutPreferenceType
	case "PaypalPayoutPreferenceType":
		u.PaypalPayoutPreferenceType = &PaypalPayoutPreferenceType{}
		payload = u.PaypalPayoutPreferenceType
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A CurrencyCloud Bank Transfer Payout Preference
type CurrencycloudBankTransferPayoutPreferenceType struct {
	ID_     *string `json:"_id,omitempty"`
	Default *bool   `json:"default,omitempty"`
	ID      *string `json:"id,omitempty"`
	Name    *string `json:"name,omitempty"`
}

// A Paypal Payout Preference
type PaypalPayoutPreferenceType struct {
	ID_     *string `json:"_id,omitempty"`
	Default *bool   `json:"default,omitempty"`
	Email   *string `json:"email,omitempty"`
	ID      *string `json:"id,omitempty"`
}

// A HackeronePayroll Payout Preference
type HackeronePayrollPayoutPreferenceType struct {
	ID_     *string `json:"_id,omitempty"`
	Default *bool   `json:"default,omitempty"`
	Email   *string `json:"email,omitempty"`
	ID      *string `json:"id,omitempty"`
}

// User invitation preference type
type InvitationPreferenceTypeEnum string

const (
	InvitationPreferenceTypeEnumAlways     InvitationPreferenceTypeEnum = "always"
	InvitationPreferenceTypeEnumBountyOnly InvitationPreferenceTypeEnum = "bounty_only"
	InvitationPreferenceTypeEnumNever      InvitationPreferenceTypeEnum = "never"
)

// A HackerOne team member
type TeamMember struct {
	// The primary key from the database
	ID_           *string   `json:"_id,omitempty"`
	AutoSubscribe *bool     `json:"auto_subscribe,omitempty"`
	Concealed     *bool     `json:"concealed,omitempty"`
	CreatedAt     *DateTime `json:"created_at,omitempty"`
	ICanLeaveTeam *bool     `json:"i_can_leave_team,omitempty"`
	ID            *string   `json:"id,omitempty"`
	Permissions   []*string `json:"permissions,omitempty"`
	SlackUserID   *string   `json:"slack_user_id,omitempty"`
	Team          *Team     `json:"team,omitempty"`
	User          *User     `json:"user,omitempty"`
}

// A HackerOne team
type Team struct {
	// The primary key from the database
	ID_                               *string             `json:"_id,omitempty"`
	About                             *string             `json:"about,omitempty"`
	Abuse                             *bool               `json:"abuse,omitempty"`
	Activities                        *ActivityConnection `json:"activities,omitempty"`
	AllowAllHackerInvitations         *bool               `json:"allow_all_hacker_invitations,omitempty"`
	AllowEmailAndAutomaticInvitations *bool               `json:"allow_email_and_automatic_invitations,omitempty"`
	AllowsPrivateDisclosure           *bool               `json:"allows_private_disclosure,omitempty"`
	AutomaticInvites                  *bool               `json:"automatic_invites,omitempty"`
	AverageBountyLowerAmount          *int32              `json:"average_bounty_lower_amount,omitempty"`
	AverageBountyUpperAmount          *int32              `json:"average_bounty_upper_amount,omitempty"`
	AwardsMiles                       *bool               `json:"awards_miles,omitempty"`
	BaseBounty                        *int32              `json:"base_bounty,omitempty"`
	Bookmarked                        *bool               `json:"bookmarked,omitempty"`
	BookmarkedTeamUsers               *UserConnection     `json:"bookmarked_team_users,omitempty"`
	BountiesTotal                     *string             `json:"bounties_total,omitempty"`
	BountyAwardedStalenessThreshold   *int32              `json:"bounty_awarded_staleness_threshold,omitempty"`
	// The participant's total bounty earned within the team
	BountyEarnedForUser                *float64                            `json:"bounty_earned_for_user,omitempty"`
	BountySplittingEnabled             *bool                               `json:"bounty_splitting_enabled,omitempty"`
	BountyTable                        *BountyTable                        `json:"bounty_table,omitempty"`
	BountyTime                         *float64                            `json:"bounty_time,omitempty"`
	BugCount                           *int32                              `json:"bug_count,omitempty"`
	ChallengeSetting                   *ChallengeSetting                   `json:"challenge_setting,omitempty"`
	ChildTeams                         *TeamConnection                     `json:"child_teams,omitempty"`
	ClaimedCredential                  *Credential                         `json:"claimed_credential,omitempty"`
	CommonResponses                    *CommonResponseConnection           `json:"common_responses,omitempty"`
	CreatedAt                          *DateTime                           `json:"created_at,omitempty"`
	CredentialInstruction              *string                             `json:"credential_instruction,omitempty"`
	CredentialInstructionHtml          *string                             `json:"credential_instruction_html,omitempty"`
	Credentials                        *CredentialConnection               `json:"credentials,omitempty"`
	CredentialsAvailableCount          *int32                              `json:"credentials_available_count,omitempty"`
	CredentialsSetUp                   *bool                               `json:"credentials_set_up,omitempty"`
	CriticalSubmissionsEnabled         *bool                               `json:"critical_submissions_enabled,omitempty"`
	Currency                           *string                             `json:"currency,omitempty"`
	CVERequests                        *CVERequestsConnection              `json:"cve_requests,omitempty"`
	CweFieldHidden                     *bool                               `json:"cwe_field_hidden,omitempty"`
	EmbeddedSubmissionDomains          *EmbeddedSubmissionDomainConnection `json:"embedded_submission_domains,omitempty"`
	EmbeddedSubmissionFormEnabled      *bool                               `json:"embedded_submission_form_enabled,omitempty"`
	EmbeddedSubmissionForms            *EmbeddedSubmissionFormConnection   `json:"embedded_submission_forms,omitempty"`
	ExternalProgram                    *ExternalProgram                    `json:"external_program,omitempty"`
	ExternalURL                        *string                             `json:"external_url,omitempty"`
	FancySlackIntegration              *bool                               `json:"fancy_slack_integration,omitempty"`
	FancySlackIntegrationEnabled       *bool                               `json:"fancy_slack_integration_enabled,omitempty"`
	FirstResponseTime                  *float64                            `json:"first_response_time,omitempty"`
	GoalValidReports                   *int32                              `json:"goal_valid_reports,omitempty"`
	GracePeriodRemainingInDays         *int32                              `json:"grace_period_remaining_in_days,omitempty"`
	HackeroneToJiraEventsConfiguration *HackeroneToJiraEventsConfiguration `json:"hackerone_to_jira_events_configuration,omitempty"`
	HackersAlsoViewed                  *TeamConnection                     `json:"hackers_also_viewed,omitempty"`
	HackersThankedCount                *int32                              `json:"hackers_thanked_count,omitempty"`
	Handle                             *string                             `json:"handle,omitempty"`
	HasAvatar                          *bool                               `json:"has_avatar,omitempty"`
	HasPolicy                          *bool                               `json:"has_policy,omitempty"`
	HasStructuredPolicy                *bool                               `json:"has_structured_policy,omitempty"`
	HideBountyAmounts                  *bool                               `json:"hide_bounty_amounts,omitempty"`
	ICanCreateJiraWebhook              *bool                               `json:"i_can_create_jira_webhook,omitempty"`
	ICanDestroyJiraWebhook             *bool                               `json:"i_can_destroy_jira_webhook,omitempty"`
	ICanManageProgram                  *bool                               `json:"i_can_manage_program,omitempty"`
	ICanViewBaseBounty                 *bool                               `json:"i_can_view_base_bounty,omitempty"`
	ICanViewBountyTable                *bool                               `json:"i_can_view_bounty_table,omitempty"`
	ICanViewCriticalSubmissionsEnabled *bool                               `json:"i_can_view_critical_submissions_enabled,omitempty"`
	ICanViewInviteHackers              *bool                               `json:"i_can_view_invite_hackers,omitempty"`
	ICanViewJiraIntegration            *bool                               `json:"i_can_view_jira_integration,omitempty"`
	ICanViewJiraWebhook                *bool                               `json:"i_can_view_jira_webhook,omitempty"`
	ICanViewPhabricatorIntegration     *bool                               `json:"i_can_view_phabricator_integration,omitempty"`
	ICanViewReportsResolved            *bool                               `json:"i_can_view_reports_resolved,omitempty"`
	ICanViewWeaknesses                 *bool                               `json:"i_can_view_weaknesses,omitempty"`
	ID                                 *string                             `json:"id,omitempty"`
	InboxViews                         *TeamInboxViewConnection            `json:"inbox_views,omitempty"`
	InsightsTeamWeaknesses             *TeamWeaknessConnection             `json:"insights_team_weaknesses,omitempty"`
	InternetBugBounty                  *bool                               `json:"internet_bug_bounty,omitempty"`
	InvitationRejectionSurveyAnswers   *SurveyAnswerConnection             `json:"invitation_rejection_survey_answers,omitempty"`
	IsReadyForPublicLaunch             *bool                               `json:"is_ready_for_public_launch,omitempty"`
	JiraIntegration                    *JiraIntegration                    `json:"jira_integration,omitempty"`
	JiraOauth                          *JiraOauth                          `json:"jira_oauth,omitempty"`
	JiraPlusPlusEnabled                *bool                               `json:"jira_plus_plus_enabled,omitempty"`
	JiraWebhook                        *JiraWebhook                        `json:"jira_webhook,omitempty"`
	// The participant's date of accepted the teams invitation
	LastInvitationAcceptedAtForUser      *DateTime `json:"last_invitation_accepted_at_for_user,omitempty"`
	LaunchLink                           *string   `json:"launch_link,omitempty"`
	MaximumNumberOfTeamMediationRequests *float64  `json:"maximum_number_of_team_mediation_requests,omitempty"`
	MinimumBounty                        *int32    `json:"minimum_bounty,omitempty"`
	Name                                 *string   `json:"name,omitempty"`
	NewStalenessThreshold                *int32    `json:"new_staleness_threshold,omitempty"`
	NewStalenessThresholdLimit           *int32    `json:"new_staleness_threshold_limit,omitempty"`
	// The participant's number of reports within the team
	NumberOfReportsForUser *int32 `json:"number_of_reports_for_user,omitempty"`
	// The participant's number of valid reports within the team
	NumberOfValidReportsForUser   *int32                            `json:"number_of_valid_reports_for_user,omitempty"`
	OffersBounties                *bool                             `json:"offers_bounties,omitempty"`
	OffersSwag                    *bool                             `json:"offers_swag,omitempty"`
	OnlyClearedHackers            *bool                             `json:"only_cleared_hackers,omitempty"`
	Participants                  *ParticipantConnection            `json:"participants,omitempty"`
	PhabricatorIntegration        *PhabricatorIntegration           `json:"phabricator_integration,omitempty"`
	Policy                        *string                           `json:"policy,omitempty"`
	PolicyHtml                    *string                           `json:"policy_html,omitempty"`
	Posts                         *TeamPostConnection               `json:"posts,omitempty"`
	ProductEdition                *ProductEdition                   `json:"product_edition,omitempty"`
	ProfileMetricsSnapshots       *ProfileMetricsSnapshotConnection `json:"profile_metrics_snapshots,omitempty"`
	ProfilePicture                *string                           `json:"profile_picture,omitempty"`
	ProgramLeaveSurveyAnswers     *SurveyAnswerConnection           `json:"program_leave_survey_answers,omitempty"`
	ProgramStatistics             *ProgramStatisticConnection       `json:"program_statistics,omitempty"`
	ReportSubmissionFormIntro     *string                           `json:"report_submission_form_intro,omitempty"`
	ReportSubmissionFormIntroHtml *string                           `json:"report_submission_form_intro_html,omitempty"`
	ReportTemplate                *string                           `json:"report_template,omitempty"`
	Reporters                     *UserConnection                   `json:"reporters,omitempty"`
	Reports                       *ReportConnection                 `json:"reports,omitempty"`
	ResolutionTime                *float64                          `json:"resolution_time,omitempty"`
	ResolvedReportCount           *int32                            `json:"resolved_report_count,omitempty"`
	ResolvedStalenessThreshold    *int32                            `json:"resolved_staleness_threshold,omitempty"`
	ResponseEfficiencyIndicator   *ResponseEfficiencyIndicatorEnum  `json:"response_efficiency_indicator,omitempty"`
	ResponseEfficiencyPercentage  *int32                            `json:"response_efficiency_percentage,omitempty"`
	ReviewRejectedAt              *DateTime                         `json:"review_rejected_at,omitempty"`
	ReviewRequestedAt             *DateTime                         `json:"review_requested_at,omitempty"`
	SettingsDisabled              *bool                             `json:"settings_disabled,omitempty"`
	SettingsLink                  *string                           `json:"settings_link,omitempty"`
	SetupGuideCompleted           *bool                             `json:"setup_guide_completed,omitempty"`
	SLAFailedCount                *int32                            `json:"sla_failed_count,omitempty"`
	SLASetting                    *SLASetting                       `json:"sla_setting,omitempty"`
	SLASnapshots                  *SLASnapshotConnection            `json:"sla_snapshots,omitempty"`
	SLAStatus                     *SLAStatus                        `json:"sla_status,omitempty"`
	SlackIntegration              *SlackIntegration                 `json:"slack_integration,omitempty"`
	SlackPipelines                *SlackPipelineConnection          `json:"slack_pipelines,omitempty"`
	// DEPRECATED: This should be a generic invitation connection. Used interim until generic invitation type is defined
	SoftLaunchInvitations          *InvitationUnionConnection        `json:"soft_launch_invitations,omitempty"`
	StartedAcceptingAt             *DateTime                         `json:"started_accepting_at,omitempty"`
	State                          *TeamState                        `json:"state,omitempty"`
	StaticParticipants             *StaticParticipantConnection      `json:"static_participants,omitempty"`
	StructuredPolicy               *StructuredPolicy                 `json:"structured_policy,omitempty"`
	StructuredScopeVersions        *StructuredScopeVersionConnection `json:"structured_scope_versions,omitempty"`
	StructuredScopes               *StructuredScopesConnection       `json:"structured_scopes,omitempty"`
	SubmissionRequirements         *SubmissionRequirements           `json:"submission_requirements,omitempty"`
	SubmissionState                *SubmissionStateEnum              `json:"submission_state,omitempty"`
	SurveyAnswers                  *SurveyAnswerConnection           `json:"survey_answers,omitempty"`
	Swag                           *SwagConnection                   `json:"swag,omitempty"`
	TargetSignal                   *float64                          `json:"target_signal,omitempty"`
	TeamDisplayOptions             *TeamDisplayOptions               `json:"team_display_options,omitempty"`
	TeamMemberGroups               []*TeamMemberGroup                `json:"team_member_groups,omitempty"`
	TeamMembers                    *TeamMemberConnection             `json:"team_members,omitempty"`
	TeamProfile                    *TeamCachedProfile                `json:"team_profile,omitempty"`
	TriageActive                   *bool                             `json:"triage_active,omitempty"`
	TriageBountyManagement         *string                           `json:"triage_bounty_management,omitempty"`
	TriageEnabled                  *bool                             `json:"triage_enabled,omitempty"`
	TriageNote                     *string                           `json:"triage_note,omitempty"`
	TriageNoteHtml                 *string                           `json:"triage_note_html,omitempty"`
	TriageTime                     *float64                          `json:"triage_time,omitempty"`
	TriagedStalenessThreshold      *int32                            `json:"triaged_staleness_threshold,omitempty"`
	TriagedStalenessThresholdLimit *int32                            `json:"triaged_staleness_threshold_limit,omitempty"`
	Triggers                       *TriggerConnection                `json:"triggers,omitempty"`
	TwitterHandle                  *string                           `json:"twitter_handle,omitempty"`
	UpdatedAt                      *DateTime                         `json:"updated_at,omitempty"`
	URL                            *URI                              `json:"url,omitempty"`
	VpnEnabled                     *bool                             `json:"vpn_enabled,omitempty"`
	Weaknesses                     *DeprecatedTeamWeaknessConnection `json:"weaknesses,omitempty"`
	Website                        *string                           `json:"website,omitempty"`
	WhitelistedHackers             *UserConnection                   `json:"whitelisted_hackers,omitempty"`
}

// Product Edition of a Team
type ProductEdition struct {
	DisplayName              *string `json:"display_name,omitempty"`
	HackerInvitationsEnabled *bool   `json:"hacker_invitations_enabled,omitempty"`
	ID                       *string `json:"id,omitempty"`
	SaasDeal                 *bool   `json:"saas_deal,omitempty"`
}

// The connection type for User.
type UserConnection struct {
	// A list of edges.
	Edges []*UserEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*User `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// Information about pagination in a connection.
type PageInfo struct {
	// When paginating forwards, the cursor to continue.
	EndCursor *string `json:"endCursor,omitempty"`
	// When paginating forwards, are there more items?
	HasNextPage *bool `json:"hasNextPage,omitempty"`
	// When paginating backwards, are there more items?
	HasPreviousPage *bool `json:"hasPreviousPage,omitempty"`
	// When paginating backwards, the cursor to continue.
	StartCursor *string `json:"startCursor,omitempty"`
}

// An edge in a connection.
type UserEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *User `json:"node,omitempty"`
}

// Different possible team states
type TeamState string

const (
	TeamStateInactive     TeamState = "inactive"
	TeamStateSandboxed    TeamState = "sandboxed"
	TeamStateDaMode       TeamState = "da_mode"
	TeamStateSoftLaunched TeamState = "soft_launched"
	TeamStatePublicMode   TeamState = "public_mode"
)

// A policy section of a HackerOne program
type StructuredPolicy struct {
	BrandPromise *string `json:"brand_promise,omitempty"`
	ID           *string `json:"id,omitempty"`
	Preferences  *string `json:"preferences,omitempty"`
	Process      *string `json:"process,omitempty"`
	SafeHarbor   *string `json:"safe_harbor,omitempty"`
	Scope        *string `json:"scope,omitempty"`
	URL          *URI    `json:"url,omitempty"`
}

// A Slack integration for a team
type SlackIntegration struct {
	// DEPRECATED: this field is not used in our new Slack integration
	Channel                  *string         `json:"channel,omitempty"`
	Channels                 []*SlackChannel `json:"channels,omitempty"`
	ID                       *string         `json:"id,omitempty"`
	ShouldFetchSlackChannels *bool           `json:"should_fetch_slack_channels,omitempty"`
	ShouldFetchSlackUsers    *bool           `json:"should_fetch_slack_users,omitempty"`
	Team                     *Team           `json:"team,omitempty"`
	TeamURL                  *string         `json:"team_url,omitempty"`
	Users                    []*SlackUser    `json:"users,omitempty"`
}

// Slack channel
type SlackChannel struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// Slack user
type SlackUser struct {
	// The id provided by Slack
	ID_         *string `json:"_id,omitempty"`
	AvatarSmall *string `json:"avatar_small,omitempty"`
	Deleted     *bool   `json:"deleted,omitempty"`
	Email       *string `json:"email,omitempty"`
	ID          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
	RealName    *string `json:"real_name,omitempty"`
}

// A JIRA integration for a team
type JiraIntegration struct {
	Assignee                      *string                                 `json:"assignee,omitempty"`
	BaseURL                       *string                                 `json:"base_url,omitempty"`
	CreatedAt                     *DateTime                               `json:"created_at,omitempty"`
	Custom                        *string                                 `json:"custom,omitempty"`
	Description                   *string                                 `json:"description,omitempty"`
	ID                            *string                                 `json:"id,omitempty"`
	IssueStatuses                 []*string                               `json:"issue_statuses,omitempty"`
	IssueType                     *int32                                  `json:"issue_type,omitempty"`
	JiraPriorityToSeverityRatings *JiraPriorityToSeverityRatingConnection `json:"jira_priority_to_severity_ratings,omitempty"`
	Labels                        *string                                 `json:"labels,omitempty"`
	Pid                           *int32                                  `json:"pid,omitempty"`
	ProjectSelectionEnabled       *bool                                   `json:"project_selection_enabled,omitempty"`
	Summary                       *string                                 `json:"summary,omitempty"`
	Team                          *Team                                   `json:"team,omitempty"`
	UpdatedAt                     *DateTime                               `json:"updated_at,omitempty"`
}

// The connection type for JiraPriorityToSeverityRating.
type JiraPriorityToSeverityRatingConnection struct {
	// A list of edges.
	Edges []*JiraPriorityToSeverityRatingEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*JiraPriorityToSeverityRating `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// An edge in a connection.
type JiraPriorityToSeverityRatingEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *JiraPriorityToSeverityRating `json:"node,omitempty"`
}

// A map of JIRA Priority to HackerOne Severity Rating
type JiraPriorityToSeverityRating struct {
	CreatedAt       *DateTime           `json:"created_at,omitempty"`
	ID              *string             `json:"id,omitempty"`
	JiraIntegration *JiraIntegration    `json:"jira_integration,omitempty"`
	PriorityID      *string             `json:"priority_id,omitempty"`
	SeverityRating  *SeverityRatingEnum `json:"severity_rating,omitempty"`
	UpdatedAt       *DateTime           `json:"updated_at,omitempty"`
}

// Severity rating
type SeverityRatingEnum string

const (
	SeverityRatingEnumNone     SeverityRatingEnum = "none"
	SeverityRatingEnumLow      SeverityRatingEnum = "low"
	SeverityRatingEnumMedium   SeverityRatingEnum = "medium"
	SeverityRatingEnumHigh     SeverityRatingEnum = "high"
	SeverityRatingEnumCritical SeverityRatingEnum = "critical"
)

// A Phabricator integration for a team
type PhabricatorIntegration struct {
	BaseURL                        *string   `json:"base_url,omitempty"`
	CreatedAt                      *DateTime `json:"created_at,omitempty"`
	Description                    *string   `json:"description,omitempty"`
	ID                             *string   `json:"id,omitempty"`
	ProcessH1CommentAdded          *bool     `json:"process_h1_comment_added,omitempty"`
	ProcessH1StatusChange          *bool     `json:"process_h1_status_change,omitempty"`
	ProcessPhabricatorCommentAdded *bool     `json:"process_phabricator_comment_added,omitempty"`
	ProcessPhabricatorStatusChange *bool     `json:"process_phabricator_status_change,omitempty"`
	ProjectTags                    *string   `json:"project_tags,omitempty"`
	Team                           *Team     `json:"team,omitempty"`
	Title                          *string   `json:"title,omitempty"`
	UpdatedAt                      *DateTime `json:"updated_at,omitempty"`
}

// Configuration for the events sent from HackerOne to JIRA
type HackeroneToJiraEventsConfiguration struct {
	AssigneeChanges   *bool   `json:"assignee_changes,omitempty"`
	Attachments       *bool   `json:"attachments,omitempty"`
	Comments          *bool   `json:"comments,omitempty"`
	ID                *string `json:"id,omitempty"`
	PublicDisclosures *bool   `json:"public_disclosures,omitempty"`
	Rewards           *bool   `json:"rewards,omitempty"`
	StateChanges      *bool   `json:"state_changes,omitempty"`
	Team              *Team   `json:"team,omitempty"`
}

// A JIRA webhook for a team
type JiraWebhook struct {
	CloseStatusID           *string   `json:"close_status_id,omitempty"`
	CreatedAt               *DateTime `json:"created_at,omitempty"`
	ID                      *string   `json:"id,omitempty"`
	LastEventReceivedAt     *DateTime `json:"last_event_received_at,omitempty"`
	LastTokenIssuedAt       *DateTime `json:"last_token_issued_at,omitempty"`
	ProcessAssigneeChange   *bool     `json:"process_assignee_change,omitempty"`
	ProcessCommentAdd       *bool     `json:"process_comment_add,omitempty"`
	ProcessPriorityChange   *bool     `json:"process_priority_change,omitempty"`
	ProcessResolutionChange *bool     `json:"process_resolution_change,omitempty"`
	ProcessStatusChange     *bool     `json:"process_status_change,omitempty"`
	Team                    *Team     `json:"team,omitempty"`
	UpdatedAt               *DateTime `json:"updated_at,omitempty"`
}

// A JIRA Oauth for a team
type JiraOauth struct {
	// Assignables for a project
	Assignables []*string `json:"assignables,omitempty"`
	Configured  *bool     `json:"configured,omitempty"`
	CreatedAt   *DateTime `json:"created_at,omitempty"`
	ID          *string   `json:"id,omitempty"`
	IssueTypes  []*string `json:"issue_types,omitempty"`
	Jwt         *bool     `json:"jwt,omitempty"`
	Priorities  []*string `json:"priorities,omitempty"`
	Projects    []*string `json:"projects,omitempty"`
	Site        *string   `json:"site,omitempty"`
	Team        *Team     `json:"team,omitempty"`
	UpdatedAt   *DateTime `json:"updated_at,omitempty"`
}

// The connection type for Team.
type TeamConnection struct {
	// A list of edges.
	Edges []*TeamEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Team `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TeamEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Team `json:"node,omitempty"`
}

// All available permissions
type PermissionEnum string

const (
	PermissionEnumProgramManagement PermissionEnum = "program_management"
)

type TeamOrderInput struct {
	Direction *OrderDirection `json:"direction,omitempty"`
	Field     *TeamOrderField `json:"field,omitempty"`
}

// Possible directions for sorting a collection
type OrderDirection string

const (
	OrderDirectionASC  OrderDirection = "ASC"
	OrderDirectionDESC OrderDirection = "DESC"
)

// Fields on which a collection of Teams can be ordered
type TeamOrderField string

const (
	TeamOrderFieldName                        TeamOrderField = "name"
	TeamOrderFieldReportsResolved             TeamOrderField = "reports_resolved"
	TeamOrderFieldAverageBountyAmount         TeamOrderField = "average_bounty_amount"
	TeamOrderFieldMinimumBounty               TeamOrderField = "minimum_bounty"
	TeamOrderFieldLastInvitationAcceptedAt    TeamOrderField = "last_invitation_accepted_at"
	TeamOrderFieldReportsSubmittedByUser      TeamOrderField = "reports_submitted_by_user"
	TeamOrderFieldValidReportsSubmittedByUser TeamOrderField = "valid_reports_submitted_by_user"
	TeamOrderFieldBountyEarnedByUser          TeamOrderField = "bounty_earned_by_user"
)

type FiltersTeamFilterOrder struct {
	Field     *FiltersTeamFilterOrderField `json:"field,omitempty"`
	Direction *FilterOrderDirectionEnum    `json:"direction,omitempty"`
}

type FiltersTeamFilterOrderField string

const (
	FiltersTeamFilterOrderFieldID                                 FiltersTeamFilterOrderField = "id"
	FiltersTeamFilterOrderFieldStartedAcceptingAt                 FiltersTeamFilterOrderField = "started_accepting_at"
	FiltersTeamFilterOrderFieldCachedResponseEfficiencyPercentage FiltersTeamFilterOrderField = "cached_response_efficiency_percentage"
)

// Possible directions for sorting a collection
type FilterOrderDirectionEnum string

const (
	FilterOrderDirectionEnumASC  FilterOrderDirectionEnum = "ASC"
	FilterOrderDirectionEnumDESC FilterOrderDirectionEnum = "DESC"
)

type FiltersTeamFilterInput struct {
	Or_                          []*FiltersTeamFilterInput             `json:"_or,omitempty"`
	And_                         []*FiltersTeamFilterInput             `json:"_and,omitempty"`
	ID                           *IntPredicateInput                    `json:"id,omitempty"`
	Name                         *StringPredicateInput                 `json:"name,omitempty"`
	Handle                       *StringPredicateInput                 `json:"handle,omitempty"`
	State                        *TeamStatePredicateInput              `json:"state,omitempty"`
	Policy                       *StringPredicateInput                 `json:"policy,omitempty"`
	OffersBounties               *BooleanPredicateInput                `json:"offers_bounties,omitempty"`
	InternetBugBounty            *BooleanPredicateInput                `json:"internet_bug_bounty,omitempty"`
	Website                      *StringPredicateInput                 `json:"website,omitempty"`
	SubmissionState              *SubmissionStateEnumPredicateInput    `json:"submission_state,omitempty"`
	ResponseEfficiencyPercentage *IntPredicateInput                    `json:"response_efficiency_percentage,omitempty"`
	ExternalProgram              *FiltersExternalProgramFilterInput    `json:"external_program,omitempty"`
	StructuredScopes             *FiltersStructuredScopeFilterInput    `json:"structured_scopes,omitempty"`
	BookmarkedTeamUsers          *FiltersUserFilterInput               `json:"bookmarked_team_users,omitempty"`
	TriageSubscriptions          *FiltersTriageSubscriptionFilterInput `json:"triage_subscriptions,omitempty"`
	WhitelistedHackers           *FiltersUserFilterInput               `json:"whitelisted_hackers,omitempty"`
	Reporters                    *FiltersUserFilterInput               `json:"reporters,omitempty"`
}

type IntPredicateInput struct {
	Eq_     *int32   `json:"_eq,omitempty"`
	Neq_    *int32   `json:"_neq,omitempty"`
	Gt_     *int32   `json:"_gt,omitempty"`
	Lt_     *int32   `json:"_lt,omitempty"`
	Gte_    *int32   `json:"_gte,omitempty"`
	Lte_    *int32   `json:"_lte,omitempty"`
	In_     []*int32 `json:"_in,omitempty"`
	Nin_    []*int32 `json:"_nin,omitempty"`
	IsNull_ *bool    `json:"_is_null,omitempty"`
}

type StringPredicateInput struct {
	Eq_       *string   `json:"_eq,omitempty"`
	Neq_      *string   `json:"_neq,omitempty"`
	Gt_       *string   `json:"_gt,omitempty"`
	Lt_       *string   `json:"_lt,omitempty"`
	Gte_      *string   `json:"_gte,omitempty"`
	Lte_      *string   `json:"_lte,omitempty"`
	In_       []*string `json:"_in,omitempty"`
	Nin_      []*string `json:"_nin,omitempty"`
	Like_     *string   `json:"_like,omitempty"`
	Nlike_    *string   `json:"_nlike,omitempty"`
	Ilike_    *string   `json:"_ilike,omitempty"`
	Nilike_   *string   `json:"_nilike,omitempty"`
	Similar_  *string   `json:"_similar,omitempty"`
	Nsimilar_ *string   `json:"_nsimilar,omitempty"`
	IsNull_   *bool     `json:"_is_null,omitempty"`
}

type TeamStatePredicateInput struct {
	Eq_     *TeamState   `json:"_eq,omitempty"`
	Neq_    *TeamState   `json:"_neq,omitempty"`
	Gt_     *TeamState   `json:"_gt,omitempty"`
	Lt_     *TeamState   `json:"_lt,omitempty"`
	Gte_    *TeamState   `json:"_gte,omitempty"`
	Lte_    *TeamState   `json:"_lte,omitempty"`
	In_     []*TeamState `json:"_in,omitempty"`
	Nin_    []*TeamState `json:"_nin,omitempty"`
	IsNull_ *bool        `json:"_is_null,omitempty"`
}

type BooleanPredicateInput struct {
	Eq_     *bool `json:"_eq,omitempty"`
	Neq_    *bool `json:"_neq,omitempty"`
	IsNull_ *bool `json:"_is_null,omitempty"`
}

type SubmissionStateEnumPredicateInput struct {
	Eq_     *SubmissionStateEnum   `json:"_eq,omitempty"`
	Neq_    *SubmissionStateEnum   `json:"_neq,omitempty"`
	Gt_     *SubmissionStateEnum   `json:"_gt,omitempty"`
	Lt_     *SubmissionStateEnum   `json:"_lt,omitempty"`
	Gte_    *SubmissionStateEnum   `json:"_gte,omitempty"`
	Lte_    *SubmissionStateEnum   `json:"_lte,omitempty"`
	In_     []*SubmissionStateEnum `json:"_in,omitempty"`
	Nin_    []*SubmissionStateEnum `json:"_nin,omitempty"`
	IsNull_ *bool                  `json:"_is_null,omitempty"`
}

// Submission states
type SubmissionStateEnum string

const (
	SubmissionStateEnumOpen     SubmissionStateEnum = "open"
	SubmissionStateEnumPaused   SubmissionStateEnum = "paused"
	SubmissionStateEnumDisabled SubmissionStateEnum = "disabled"
)

type FiltersExternalProgramFilterInput struct {
	Or_           []*FiltersExternalProgramFilterInput `json:"_or,omitempty"`
	And_          []*FiltersExternalProgramFilterInput `json:"_and,omitempty"`
	ID            *IntPredicateInput                   `json:"id,omitempty"`
	OffersRewards *BooleanPredicateInput               `json:"offers_rewards,omitempty"`
	Policy        *StringPredicateInput                `json:"policy,omitempty"`
	Name          *StringPredicateInput                `json:"name,omitempty"`
	Website       *StringPredicateInput                `json:"website,omitempty"`
}

type FiltersStructuredScopeFilterInput struct {
	Or_             []*FiltersStructuredScopeFilterInput        `json:"_or,omitempty"`
	And_            []*FiltersStructuredScopeFilterInput        `json:"_and,omitempty"`
	ID              *IntPredicateInput                          `json:"id,omitempty"`
	AssetIdentifier *StringPredicateInput                       `json:"asset_identifier,omitempty"`
	AssetType       *StructuredScopeAssetTypeEnumPredicateInput `json:"asset_type,omitempty"`
}

type StructuredScopeAssetTypeEnumPredicateInput struct {
	Eq_     *StructuredScopeAssetTypeEnum   `json:"_eq,omitempty"`
	Neq_    *StructuredScopeAssetTypeEnum   `json:"_neq,omitempty"`
	Gt_     *StructuredScopeAssetTypeEnum   `json:"_gt,omitempty"`
	Lt_     *StructuredScopeAssetTypeEnum   `json:"_lt,omitempty"`
	Gte_    *StructuredScopeAssetTypeEnum   `json:"_gte,omitempty"`
	Lte_    *StructuredScopeAssetTypeEnum   `json:"_lte,omitempty"`
	In_     []*StructuredScopeAssetTypeEnum `json:"_in,omitempty"`
	Nin_    []*StructuredScopeAssetTypeEnum `json:"_nin,omitempty"`
	IsNull_ *bool                           `json:"_is_null,omitempty"`
}

// Structured Scope asset type enum
type StructuredScopeAssetTypeEnum string

const (
	StructuredScopeAssetTypeEnumCIDR                    StructuredScopeAssetTypeEnum = "CIDR"
	StructuredScopeAssetTypeEnumURL                     StructuredScopeAssetTypeEnum = "URL"
	StructuredScopeAssetTypeEnumAPPLESTOREAPPID         StructuredScopeAssetTypeEnum = "APPLE_STORE_APP_ID"
	StructuredScopeAssetTypeEnumTESTFLIGHT              StructuredScopeAssetTypeEnum = "TESTFLIGHT"
	StructuredScopeAssetTypeEnumOTHERIPA                StructuredScopeAssetTypeEnum = "OTHER_IPA"
	StructuredScopeAssetTypeEnumGOOGLEPLAYAPPID         StructuredScopeAssetTypeEnum = "GOOGLE_PLAY_APP_ID"
	StructuredScopeAssetTypeEnumOTHERAPK                StructuredScopeAssetTypeEnum = "OTHER_APK"
	StructuredScopeAssetTypeEnumWINDOWSAPPSTOREAPPID    StructuredScopeAssetTypeEnum = "WINDOWS_APP_STORE_APP_ID"
	StructuredScopeAssetTypeEnumSOURCECODE              StructuredScopeAssetTypeEnum = "SOURCE_CODE"
	StructuredScopeAssetTypeEnumDOWNLOADABLEEXECUTABLES StructuredScopeAssetTypeEnum = "DOWNLOADABLE_EXECUTABLES"
	StructuredScopeAssetTypeEnumHARDWARE                StructuredScopeAssetTypeEnum = "HARDWARE"
	StructuredScopeAssetTypeEnumOTHER                   StructuredScopeAssetTypeEnum = "OTHER"
)

type FiltersUserFilterInput struct {
	Or_      []*FiltersUserFilterInput `json:"_or,omitempty"`
	And_     []*FiltersUserFilterInput `json:"_and,omitempty"`
	ID       *IntPredicateInput        `json:"id,omitempty"`
	Username *StringPredicateInput     `json:"username,omitempty"`
	IsMe     *bool                     `json:"is_me,omitempty"`
}

type FiltersTriageSubscriptionFilterInput struct {
	Or_      []*FiltersTriageSubscriptionFilterInput `json:"_or,omitempty"`
	And_     []*FiltersTriageSubscriptionFilterInput `json:"_and,omitempty"`
	ID       *IntPredicateInput                      `json:"id,omitempty"`
	IsActive *bool                                   `json:"is_active,omitempty"`
}

// Challenge setting of a Team
type ChallengeSetting struct {
	ID         *string `json:"id,omitempty"`
	NotStarted *bool   `json:"not_started,omitempty"`
	Policy     *string `json:"policy,omitempty"`
}

// The connection type for EmbeddedSubmissionDomain.
type EmbeddedSubmissionDomainConnection struct {
	// A list of edges.
	Edges []*EmbeddedSubmissionDomainEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*EmbeddedSubmissionDomain `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type EmbeddedSubmissionDomainEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *EmbeddedSubmissionDomain `json:"node,omitempty"`
}

// Allowed domains for embedded submission forms
type EmbeddedSubmissionDomain struct {
	ID_       *string `json:"_id,omitempty"`
	CreatedBy *User   `json:"created_by,omitempty"`
	Domain    *string `json:"domain,omitempty"`
	ID        *string `json:"id,omitempty"`
	Team      *Team   `json:"team,omitempty"`
}

// The connection type for EmbeddedSubmissionForm.
type EmbeddedSubmissionFormConnection struct {
	// A list of edges.
	Edges []*EmbeddedSubmissionFormEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*EmbeddedSubmissionForm `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type EmbeddedSubmissionFormEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *EmbeddedSubmissionForm `json:"node,omitempty"`
}

// Embedded submission form
type EmbeddedSubmissionForm struct {
	ID   *string `json:"id,omitempty"`
	Team *Team   `json:"team,omitempty"`
	Uuid *string `json:"uuid,omitempty"`
}

// The connection type for Credential.
type CredentialConnection struct {
	// A list of edges.
	Edges []*CredentialEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Credential `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type CredentialEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Credential `json:"node,omitempty"`
}

// Credentials of a team
type Credential struct {
	ID_            *string `json:"_id,omitempty"`
	AccountDetails *string `json:"account_details,omitempty"`
	Credentials    *string `json:"credentials,omitempty"`
	ID             *string `json:"id,omitempty"`
	Revoked        *bool   `json:"revoked,omitempty"`
	User           *User   `json:"user,omitempty"`
}

// SLA Status of a Team
type SLAStatus struct {
	ID                     *string `json:"id,omitempty"`
	Team                   *Team   `json:"team,omitempty"`
	TriageSLAFailInHours   *int32  `json:"triage_sla_fail_in_hours,omitempty"`
	TriageSLAFailuresCount *int32  `json:"triage_sla_failures_count,omitempty"`
	TriageSLAMissesCount   *int32  `json:"triage_sla_misses_count,omitempty"`
	TriageSLAOkCount       *int32  `json:"triage_sla_ok_count,omitempty"`
	UserID                 *int32  `json:"user_id,omitempty"`
}

// The connection type for ProgramStatistic.
type ProgramStatisticConnection struct {
	// A list of edges.
	Edges []*ProgramStatisticEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ProgramStatistic `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type ProgramStatisticEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ProgramStatistic `json:"node,omitempty"`
}

// Statistics for a certain interval for a certain team
type ProgramStatistic struct {
	DuplicateReports             *int32                             `json:"duplicate_reports,omitempty"`
	ID                           *string                            `json:"id,omitempty"`
	InformativeReports           *int32                             `json:"informative_reports,omitempty"`
	Interval                     *ProgramStatisticIntervalEnum      `json:"interval,omitempty"`
	IntervalStart                *Date                              `json:"interval_start,omitempty"`
	IsComplete                   *bool                              `json:"is_complete,omitempty"`
	NotApplicableReports         *int32                             `json:"not_applicable_reports,omitempty"`
	ResolvedReports              *int32                             `json:"resolved_reports,omitempty"`
	SpamReports                  *int32                             `json:"spam_reports,omitempty"`
	SubmittedReports             *int32                             `json:"submitted_reports,omitempty"`
	TriagedReports               *int32                             `json:"triaged_reports,omitempty"`
	ValidCriticalSeverityReports *int32                             `json:"valid_critical_severity_reports,omitempty"`
	ValidHighSeverityReports     *int32                             `json:"valid_high_severity_reports,omitempty"`
	ValidLowSeverityReports      *int32                             `json:"valid_low_severity_reports,omitempty"`
	ValidMediumSeverityReports   *int32                             `json:"valid_medium_severity_reports,omitempty"`
	ValidNoSeverityReports       *int32                             `json:"valid_no_severity_reports,omitempty"`
	ValidReports                 *int32                             `json:"valid_reports,omitempty"`
	ValidReportsPerScope         *ReportsCountPerScopeConnection    `json:"valid_reports_per_scope,omitempty"`
	ValidReportsPerWeakness      *ReportsCountPerWeaknessConnection `json:"valid_reports_per_weakness,omitempty"`
}

// Intervals that program statistics can be grouped by
type ProgramStatisticIntervalEnum string

const (
	ProgramStatisticIntervalEnumDay     ProgramStatisticIntervalEnum = "day"
	ProgramStatisticIntervalEnumMonth   ProgramStatisticIntervalEnum = "month"
	ProgramStatisticIntervalEnumQuarter ProgramStatisticIntervalEnum = "quarter"
	ProgramStatisticIntervalEnumYear    ProgramStatisticIntervalEnum = "year"
)

// The connection type for ReportsCountPerScope.
type ReportsCountPerScopeConnection struct {
	// A list of edges.
	Edges []*ReportsCountPerScopeEdge `json:"edges,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ReportsCountPerScopeEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ReportsCountPerScope `json:"node,omitempty"`
}

// Number of reports per scope of specific program
type ReportsCountPerScope struct {
	AssetIdentifier *string `json:"asset_identifier,omitempty"`
	ID              *string `json:"id,omitempty"`
	ReportsCount    *int32  `json:"reports_count,omitempty"`
}

// The connection type for ReportsCountPerWeakness.
type ReportsCountPerWeaknessConnection struct {
	// A list of edges.
	Edges []*ReportsCountPerWeaknessEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ReportsCountPerWeakness `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ReportsCountPerWeaknessEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ReportsCountPerWeakness `json:"node,omitempty"`
}

// Number of reports per weakness of specific program
type ReportsCountPerWeakness struct {
	ID           *string   `json:"id,omitempty"`
	ReportsCount *int32    `json:"reports_count,omitempty"`
	Weakness     *Weakness `json:"weakness,omitempty"`
}

// The type of vulnerability on a HackerOne report
type Weakness struct {
	ID_         *string            `json:"_id,omitempty"`
	Clusters    *ClusterConnection `json:"clusters,omitempty"`
	CreatedAt   *DateTime          `json:"created_at,omitempty"`
	Description *string            `json:"description,omitempty"`
	ExternalID  *string            `json:"external_id,omitempty"`
	ID          *string            `json:"id,omitempty"`
	Name        *string            `json:"name,omitempty"`
	UpdatedAt   *DateTime          `json:"updated_at,omitempty"`
}

// The connection type for Cluster.
type ClusterConnection struct {
	// A list of edges.
	Edges []*ClusterEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Cluster `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ClusterEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Cluster `json:"node,omitempty"`
}

// A subset of weaknesses that share a common characteristic
type Cluster struct {
	CreatedAt   *DateTime                  `json:"created_at,omitempty"`
	Description *string                    `json:"description,omitempty"`
	ID          *string                    `json:"id,omitempty"`
	Name        *string                    `json:"name,omitempty"`
	UpdatedAt   *DateTime                  `json:"updated_at,omitempty"`
	Weaknesses  *ClusterWeaknessConnection `json:"weaknesses,omitempty"`
}

// The connection type for Weakness.
type ClusterWeaknessConnection struct {
	// A list of edges.
	Edges []*ClusterWeaknessEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Weakness `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ClusterWeaknessEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node         *Weakness     `json:"node,omitempty"`
	TeamWeakness *TeamWeakness `json:"team_weakness,omitempty"`
}

// Team configuration of a weakness
type TeamWeakness struct {
	ID          *string             `json:"id,omitempty"`
	Instruction *string             `json:"instruction,omitempty"`
	ReportCount *int32              `json:"report_count,omitempty"`
	State       *TeamWeaknessStates `json:"state,omitempty"`
	Team        *Team               `json:"team,omitempty"`
	Weakness    *Weakness           `json:"weakness,omitempty"`
}

// Possible states of how a weakness can be configured for a team
type TeamWeaknessStates string

const (
	TeamWeaknessStatesDisabled TeamWeaknessStates = "disabled"
	TeamWeaknessStatesEnabled  TeamWeaknessStates = "enabled"
	TeamWeaknessStatesHidden   TeamWeaknessStates = "hidden"
)

type WeaknessOrder struct {
	Direction *OrderDirection     `json:"direction,omitempty"`
	Field     *WeaknessOrderField `json:"field,omitempty"`
}

// Fields on which a collection of weaknesses can be ordered
type WeaknessOrderField string

const (
	WeaknessOrderFieldName WeaknessOrderField = "name"
)

type ClusterOrder struct {
	Direction *OrderDirection    `json:"direction,omitempty"`
	Field     *ClusterOrderField `json:"field,omitempty"`
}

// Fields on which a collection of Cluster can be ordered
type ClusterOrderField string

const (
	ClusterOrderFieldBROWSINGFRIENDLY ClusterOrderField = "BROWSING_FRIENDLY"
)

// The connection type for SlaSnapshot.
type SLASnapshotConnection struct {
	// A list of edges.
	Edges   []*SLASnapshotEdge       `json:"edges,omitempty"`
	GroupBy []*AggregatedSLASnapshot `json:"group_by,omitempty"`
	// A list of nodes.
	Nodes []*SLASnapshot `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type SLASnapshotEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *SLASnapshot `json:"node,omitempty"`
}

// SLA snapshot of a Team
type SLASnapshot struct {
	AverageTimeToBountyAwarded           *float64  `json:"average_time_to_bounty_awarded,omitempty"`
	AverageTimeToFirstProgramResponse    *float64  `json:"average_time_to_first_program_response,omitempty"`
	AverageTimeToReportResolved          *float64  `json:"average_time_to_report_resolved,omitempty"`
	AverageTimeToReportTriage            *float64  `json:"average_time_to_report_triage,omitempty"`
	BountyAwardedSLAMissesCount          *int32    `json:"bounty_awarded_sla_misses_count,omitempty"`
	CreatedAt                            *DateTime `json:"created_at,omitempty"`
	FirstProgramResponseSLAFailuresCount *int32    `json:"first_program_response_sla_failures_count,omitempty"`
	FirstProgramResponseSLAMissesCount   *int32    `json:"first_program_response_sla_misses_count,omitempty"`
	ID                                   *string   `json:"id,omitempty"`
	ReportResolvedSLAMissesCount         *int32    `json:"report_resolved_sla_misses_count,omitempty"`
	ReportTriageSLAFailuresCount         *int32    `json:"report_triage_sla_failures_count,omitempty"`
	ReportTriageSLAMissesCount           *int32    `json:"report_triage_sla_misses_count,omitempty"`
	SLAFailuresCount                     *int32    `json:"sla_failures_count,omitempty"`
	SLAMissesCount                       *int32    `json:"sla_misses_count,omitempty"`
	SLAOnTargetCount                     *int32    `json:"sla_on_target_count,omitempty"`
	Team                                 *Team     `json:"team,omitempty"`
}

// An SLA snapshot aggregate
type AggregatedSLASnapshot struct {
	AverageTimeToBountyAwarded        *float64  `json:"average_time_to_bounty_awarded,omitempty"`
	AverageTimeToFirstProgramResponse *float64  `json:"average_time_to_first_program_response,omitempty"`
	AverageTimeToReportResolved       *float64  `json:"average_time_to_report_resolved,omitempty"`
	AverageTimeToReportTriage         *float64  `json:"average_time_to_report_triage,omitempty"`
	Timestamp                         *DateTime `json:"timestamp,omitempty"`
}

// Time intervals sla snapshots can be grouped by
type SLASnapshotIntervalEnum string

const (
	SLASnapshotIntervalEnumDay   SLASnapshotIntervalEnum = "day"
	SLASnapshotIntervalEnumWeek  SLASnapshotIntervalEnum = "week"
	SLASnapshotIntervalEnumMonth SLASnapshotIntervalEnum = "month"
)

// Fields on which a collection of SLA snapshots can be filtered
type SLASnapshotFilterField string

const (
	SLASnapshotFilterFieldPREVIOUSWEEK SLASnapshotFilterField = "PREVIOUS_WEEK"
)

// Cached metrics of a Team
type TeamCachedProfile struct {
	ID_                               *string   `json:"_id,omitempty"`
	DisclosedReportsInLastYearCount   *int32    `json:"disclosed_reports_in_last_year_count,omitempty"`
	HackersAcceptedAllTimeCount       *int32    `json:"hackers_accepted_all_time_count,omitempty"`
	HackersInvitedAllTimeCount        *int32    `json:"hackers_invited_all_time_count,omitempty"`
	ID                                *string   `json:"id,omitempty"`
	LatestReportCreatedAt             *DateTime `json:"latest_report_created_at,omitempty"`
	LatestSeriousReportTriagedAt      *DateTime `json:"latest_serious_report_triaged_at,omitempty"`
	RecentlyParticipatingHackersCount *int32    `json:"recently_participating_hackers_count,omitempty"`
	ReportsReceivedInThreeMonthsCount *int32    `json:"reports_received_in_three_months_count,omitempty"`
}

// The connection type for ActivityUnion.
type ActivityConnection struct {
	// A list of edges.
	Edges        []*ActivityUnionEdge `json:"edges,omitempty"`
	MaxUpdatedAt *DateTime            `json:"max_updated_at,omitempty"`
	// A list of nodes.
	Nodes []*ActivityUnion `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ActivityUnionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ActivityUnion `json:"node,omitempty"`
}

// Activities can be of multiple types
type ActivityUnion struct {
	TypeName__                                string                                     `json:"__typename,omitempty"`
	ActivitiesAgreedOnGoingPublic             *ActivitiesAgreedOnGoingPublic             `json:"-"`
	ActivitiesBountyAwarded                   *ActivitiesBountyAwarded                   `json:"-"`
	ActivitiesBountySuggested                 *ActivitiesBountySuggested                 `json:"-"`
	ActivitiesBugCloned                       *ActivitiesBugCloned                       `json:"-"`
	ActivitiesBugDuplicate                    *ActivitiesBugDuplicate                    `json:"-"`
	ActivitiesBugInformative                  *ActivitiesBugInformative                  `json:"-"`
	ActivitiesBugNeedsMoreInfo                *ActivitiesBugNeedsMoreInfo                `json:"-"`
	ActivitiesBugNew                          *ActivitiesBugNew                          `json:"-"`
	ActivitiesBugNotApplicable                *ActivitiesBugNotApplicable                `json:"-"`
	ActivitiesBugInactive                     *ActivitiesBugInactive                     `json:"-"`
	ActivitiesBugReopened                     *ActivitiesBugReopened                     `json:"-"`
	ActivitiesBugResolved                     *ActivitiesBugResolved                     `json:"-"`
	ActivitiesBugSpam                         *ActivitiesBugSpam                         `json:"-"`
	ActivitiesBugTriaged                      *ActivitiesBugTriaged                      `json:"-"`
	ActivitiesBugFiled                        *ActivitiesBugFiled                        `json:"-"`
	ActivitiesCancelledDisclosureRequest      *ActivitiesCancelledDisclosureRequest      `json:"-"`
	ActivitiesChangedScope                    *ActivitiesChangedScope                    `json:"-"`
	ActivitiesComment                         *ActivitiesComment                         `json:"-"`
	ActivitiesCommentsClosed                  *ActivitiesCommentsClosed                  `json:"-"`
	ActivitiesExternalUserInvitationCancelled *ActivitiesExternalUserInvitationCancelled `json:"-"`
	ActivitiesExternalAdvisoryAdded           *ActivitiesExternalAdvisoryAdded           `json:"-"`
	ActivitiesExternalUserInvited             *ActivitiesExternalUserInvited             `json:"-"`
	ActivitiesExternalUserJoined              *ActivitiesExternalUserJoined              `json:"-"`
	ActivitiesExternalUserRemoved             *ActivitiesExternalUserRemoved             `json:"-"`
	ActivitiesGroupAssignedToBug              *ActivitiesGroupAssignedToBug              `json:"-"`
	ActivitiesHackerRequestedMediation        *ActivitiesHackerRequestedMediation        `json:"-"`
	ActivitiesManuallyDisclosed               *ActivitiesManuallyDisclosed               `json:"-"`
	ActivitiesMediationRequested              *ActivitiesMediationRequested              `json:"-"`
	ActivitiesNotEligibleForBounty            *ActivitiesNotEligibleForBounty            `json:"-"`
	ActivitiesReferenceIDAdded                *ActivitiesReferenceIDAdded                `json:"-"`
	ActivitiesCVEIDAdded                      *ActivitiesCVEIDAdded                      `json:"-"`
	ActivitiesReassignedToTeam                *ActivitiesReassignedToTeam                `json:"-"`
	ActivitiesReportBecamePublic              *ActivitiesReportBecamePublic              `json:"-"`
	ActivitiesReportTitleUpdated              *ActivitiesReportTitleUpdated              `json:"-"`
	ActivitiesReportVulnerabilityTypesUpdated *ActivitiesReportVulnerabilityTypesUpdated `json:"-"`
	ActivitiesReportSeverityUpdated           *ActivitiesReportSeverityUpdated           `json:"-"`
	ActivitiesReportCollaboratorInvited       *ActivitiesReportCollaboratorInvited       `json:"-"`
	ActivitiesReportCollaboratorJoined        *ActivitiesReportCollaboratorJoined        `json:"-"`
	ActivitiesSwagAwarded                     *ActivitiesSwagAwarded                     `json:"-"`
	ActivitiesTeamPublished                   *ActivitiesTeamPublished                   `json:"-"`
	ActivitiesUserAssignedToBug               *ActivitiesUserAssignedToBug               `json:"-"`
	ActivitiesUserBannedFromProgram           *ActivitiesUserBannedFromProgram           `json:"-"`
	ActivitiesUserJoined                      *ActivitiesUserJoined                      `json:"-"`
	ActivitiesNobodyAssignedToBug             *ActivitiesNobodyAssignedToBug             `json:"-"`
	ActivitiesProgramInactive                 *ActivitiesProgramInactive                 `json:"-"`
	ActivitiesUserCompletedRetest             *ActivitiesUserCompletedRetest             `json:"-"`
}

func (u *ActivityUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType ActivityUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "ActivitiesAgreedOnGoingPublic":
		u.ActivitiesAgreedOnGoingPublic = &ActivitiesAgreedOnGoingPublic{}
		payload = u.ActivitiesAgreedOnGoingPublic
	case "ActivitiesBountyAwarded":
		u.ActivitiesBountyAwarded = &ActivitiesBountyAwarded{}
		payload = u.ActivitiesBountyAwarded
	case "ActivitiesBountySuggested":
		u.ActivitiesBountySuggested = &ActivitiesBountySuggested{}
		payload = u.ActivitiesBountySuggested
	case "ActivitiesBugCloned":
		u.ActivitiesBugCloned = &ActivitiesBugCloned{}
		payload = u.ActivitiesBugCloned
	case "ActivitiesBugDuplicate":
		u.ActivitiesBugDuplicate = &ActivitiesBugDuplicate{}
		payload = u.ActivitiesBugDuplicate
	case "ActivitiesBugInformative":
		u.ActivitiesBugInformative = &ActivitiesBugInformative{}
		payload = u.ActivitiesBugInformative
	case "ActivitiesBugNeedsMoreInfo":
		u.ActivitiesBugNeedsMoreInfo = &ActivitiesBugNeedsMoreInfo{}
		payload = u.ActivitiesBugNeedsMoreInfo
	case "ActivitiesBugNew":
		u.ActivitiesBugNew = &ActivitiesBugNew{}
		payload = u.ActivitiesBugNew
	case "ActivitiesBugNotApplicable":
		u.ActivitiesBugNotApplicable = &ActivitiesBugNotApplicable{}
		payload = u.ActivitiesBugNotApplicable
	case "ActivitiesBugInactive":
		u.ActivitiesBugInactive = &ActivitiesBugInactive{}
		payload = u.ActivitiesBugInactive
	case "ActivitiesBugReopened":
		u.ActivitiesBugReopened = &ActivitiesBugReopened{}
		payload = u.ActivitiesBugReopened
	case "ActivitiesBugResolved":
		u.ActivitiesBugResolved = &ActivitiesBugResolved{}
		payload = u.ActivitiesBugResolved
	case "ActivitiesBugSpam":
		u.ActivitiesBugSpam = &ActivitiesBugSpam{}
		payload = u.ActivitiesBugSpam
	case "ActivitiesBugTriaged":
		u.ActivitiesBugTriaged = &ActivitiesBugTriaged{}
		payload = u.ActivitiesBugTriaged
	case "ActivitiesBugFiled":
		u.ActivitiesBugFiled = &ActivitiesBugFiled{}
		payload = u.ActivitiesBugFiled
	case "ActivitiesCancelledDisclosureRequest":
		u.ActivitiesCancelledDisclosureRequest = &ActivitiesCancelledDisclosureRequest{}
		payload = u.ActivitiesCancelledDisclosureRequest
	case "ActivitiesChangedScope":
		u.ActivitiesChangedScope = &ActivitiesChangedScope{}
		payload = u.ActivitiesChangedScope
	case "ActivitiesComment":
		u.ActivitiesComment = &ActivitiesComment{}
		payload = u.ActivitiesComment
	case "ActivitiesCommentsClosed":
		u.ActivitiesCommentsClosed = &ActivitiesCommentsClosed{}
		payload = u.ActivitiesCommentsClosed
	case "ActivitiesExternalUserInvitationCancelled":
		u.ActivitiesExternalUserInvitationCancelled = &ActivitiesExternalUserInvitationCancelled{}
		payload = u.ActivitiesExternalUserInvitationCancelled
	case "ActivitiesExternalAdvisoryAdded":
		u.ActivitiesExternalAdvisoryAdded = &ActivitiesExternalAdvisoryAdded{}
		payload = u.ActivitiesExternalAdvisoryAdded
	case "ActivitiesExternalUserInvited":
		u.ActivitiesExternalUserInvited = &ActivitiesExternalUserInvited{}
		payload = u.ActivitiesExternalUserInvited
	case "ActivitiesExternalUserJoined":
		u.ActivitiesExternalUserJoined = &ActivitiesExternalUserJoined{}
		payload = u.ActivitiesExternalUserJoined
	case "ActivitiesExternalUserRemoved":
		u.ActivitiesExternalUserRemoved = &ActivitiesExternalUserRemoved{}
		payload = u.ActivitiesExternalUserRemoved
	case "ActivitiesGroupAssignedToBug":
		u.ActivitiesGroupAssignedToBug = &ActivitiesGroupAssignedToBug{}
		payload = u.ActivitiesGroupAssignedToBug
	case "ActivitiesHackerRequestedMediation":
		u.ActivitiesHackerRequestedMediation = &ActivitiesHackerRequestedMediation{}
		payload = u.ActivitiesHackerRequestedMediation
	case "ActivitiesManuallyDisclosed":
		u.ActivitiesManuallyDisclosed = &ActivitiesManuallyDisclosed{}
		payload = u.ActivitiesManuallyDisclosed
	case "ActivitiesMediationRequested":
		u.ActivitiesMediationRequested = &ActivitiesMediationRequested{}
		payload = u.ActivitiesMediationRequested
	case "ActivitiesNotEligibleForBounty":
		u.ActivitiesNotEligibleForBounty = &ActivitiesNotEligibleForBounty{}
		payload = u.ActivitiesNotEligibleForBounty
	case "ActivitiesReferenceIDAdded":
		u.ActivitiesReferenceIDAdded = &ActivitiesReferenceIDAdded{}
		payload = u.ActivitiesReferenceIDAdded
	case "ActivitiesCVEIDAdded":
		u.ActivitiesCVEIDAdded = &ActivitiesCVEIDAdded{}
		payload = u.ActivitiesCVEIDAdded
	case "ActivitiesReassignedToTeam":
		u.ActivitiesReassignedToTeam = &ActivitiesReassignedToTeam{}
		payload = u.ActivitiesReassignedToTeam
	case "ActivitiesReportBecamePublic":
		u.ActivitiesReportBecamePublic = &ActivitiesReportBecamePublic{}
		payload = u.ActivitiesReportBecamePublic
	case "ActivitiesReportTitleUpdated":
		u.ActivitiesReportTitleUpdated = &ActivitiesReportTitleUpdated{}
		payload = u.ActivitiesReportTitleUpdated
	case "ActivitiesReportVulnerabilityTypesUpdated":
		u.ActivitiesReportVulnerabilityTypesUpdated = &ActivitiesReportVulnerabilityTypesUpdated{}
		payload = u.ActivitiesReportVulnerabilityTypesUpdated
	case "ActivitiesReportSeverityUpdated":
		u.ActivitiesReportSeverityUpdated = &ActivitiesReportSeverityUpdated{}
		payload = u.ActivitiesReportSeverityUpdated
	case "ActivitiesReportCollaboratorInvited":
		u.ActivitiesReportCollaboratorInvited = &ActivitiesReportCollaboratorInvited{}
		payload = u.ActivitiesReportCollaboratorInvited
	case "ActivitiesReportCollaboratorJoined":
		u.ActivitiesReportCollaboratorJoined = &ActivitiesReportCollaboratorJoined{}
		payload = u.ActivitiesReportCollaboratorJoined
	case "ActivitiesSwagAwarded":
		u.ActivitiesSwagAwarded = &ActivitiesSwagAwarded{}
		payload = u.ActivitiesSwagAwarded
	case "ActivitiesTeamPublished":
		u.ActivitiesTeamPublished = &ActivitiesTeamPublished{}
		payload = u.ActivitiesTeamPublished
	case "ActivitiesUserAssignedToBug":
		u.ActivitiesUserAssignedToBug = &ActivitiesUserAssignedToBug{}
		payload = u.ActivitiesUserAssignedToBug
	case "ActivitiesUserBannedFromProgram":
		u.ActivitiesUserBannedFromProgram = &ActivitiesUserBannedFromProgram{}
		payload = u.ActivitiesUserBannedFromProgram
	case "ActivitiesUserJoined":
		u.ActivitiesUserJoined = &ActivitiesUserJoined{}
		payload = u.ActivitiesUserJoined
	case "ActivitiesNobodyAssignedToBug":
		u.ActivitiesNobodyAssignedToBug = &ActivitiesNobodyAssignedToBug{}
		payload = u.ActivitiesNobodyAssignedToBug
	case "ActivitiesProgramInactive":
		u.ActivitiesProgramInactive = &ActivitiesProgramInactive{}
		payload = u.ActivitiesProgramInactive
	case "ActivitiesUserCompletedRetest":
		u.ActivitiesUserCompletedRetest = &ActivitiesUserCompletedRetest{}
		payload = u.ActivitiesUserCompletedRetest
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A Activities::AgreedOnGoingPublic activity for a report
type ActivitiesAgreedOnGoingPublic struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	FirstToAgree      *bool         `json:"first_to_agree,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A interface for the common fields on an HackerOne Activity
type ActivityInterface struct {
	ID_                                       *string                                    `json:"_id,omitempty"`
	Actor                                     *ActorUnion                                `json:"actor,omitempty"`
	CreatedAt                                 *DateTime                                  `json:"created_at,omitempty"`
	ICanEdit                                  *bool                                      `json:"i_can_edit,omitempty"`
	Internal                                  *bool                                      `json:"internal,omitempty"`
	MarkdownMessage                           *string                                    `json:"markdown_message,omitempty"`
	Message                                   *string                                    `json:"message,omitempty"`
	UpdatedAt                                 *DateTime                                  `json:"updated_at,omitempty"`
	TypeName__                                string                                     `json:"__typename,omitempty"`
	ActivitiesAgreedOnGoingPublic             *ActivitiesAgreedOnGoingPublic             `json:"-"`
	ActivitiesBountyAwarded                   *ActivitiesBountyAwarded                   `json:"-"`
	ActivitiesBountySuggested                 *ActivitiesBountySuggested                 `json:"-"`
	ActivitiesBugCloned                       *ActivitiesBugCloned                       `json:"-"`
	ActivitiesBugDuplicate                    *ActivitiesBugDuplicate                    `json:"-"`
	ActivitiesBugFiled                        *ActivitiesBugFiled                        `json:"-"`
	ActivitiesBugInactive                     *ActivitiesBugInactive                     `json:"-"`
	ActivitiesBugInformative                  *ActivitiesBugInformative                  `json:"-"`
	ActivitiesBugNeedsMoreInfo                *ActivitiesBugNeedsMoreInfo                `json:"-"`
	ActivitiesBugNew                          *ActivitiesBugNew                          `json:"-"`
	ActivitiesBugNotApplicable                *ActivitiesBugNotApplicable                `json:"-"`
	ActivitiesBugReopened                     *ActivitiesBugReopened                     `json:"-"`
	ActivitiesBugResolved                     *ActivitiesBugResolved                     `json:"-"`
	ActivitiesBugSpam                         *ActivitiesBugSpam                         `json:"-"`
	ActivitiesBugTriaged                      *ActivitiesBugTriaged                      `json:"-"`
	ActivitiesCancelledDisclosureRequest      *ActivitiesCancelledDisclosureRequest      `json:"-"`
	ActivitiesChangedScope                    *ActivitiesChangedScope                    `json:"-"`
	ActivitiesComment                         *ActivitiesComment                         `json:"-"`
	ActivitiesCommentsClosed                  *ActivitiesCommentsClosed                  `json:"-"`
	ActivitiesCVEIDAdded                      *ActivitiesCVEIDAdded                      `json:"-"`
	ActivitiesExternalAdvisoryAdded           *ActivitiesExternalAdvisoryAdded           `json:"-"`
	ActivitiesExternalUserInvitationCancelled *ActivitiesExternalUserInvitationCancelled `json:"-"`
	ActivitiesExternalUserInvited             *ActivitiesExternalUserInvited             `json:"-"`
	ActivitiesExternalUserJoined              *ActivitiesExternalUserJoined              `json:"-"`
	ActivitiesExternalUserRemoved             *ActivitiesExternalUserRemoved             `json:"-"`
	ActivitiesGroupAssignedToBug              *ActivitiesGroupAssignedToBug              `json:"-"`
	ActivitiesHackerRequestedMediation        *ActivitiesHackerRequestedMediation        `json:"-"`
	ActivitiesManuallyDisclosed               *ActivitiesManuallyDisclosed               `json:"-"`
	ActivitiesMediationRequested              *ActivitiesMediationRequested              `json:"-"`
	ActivitiesNobodyAssignedToBug             *ActivitiesNobodyAssignedToBug             `json:"-"`
	ActivitiesNotEligibleForBounty            *ActivitiesNotEligibleForBounty            `json:"-"`
	ActivitiesProgramInactive                 *ActivitiesProgramInactive                 `json:"-"`
	ActivitiesReassignedToTeam                *ActivitiesReassignedToTeam                `json:"-"`
	ActivitiesReferenceIDAdded                *ActivitiesReferenceIDAdded                `json:"-"`
	ActivitiesReportBecamePublic              *ActivitiesReportBecamePublic              `json:"-"`
	ActivitiesReportCollaboratorInvited       *ActivitiesReportCollaboratorInvited       `json:"-"`
	ActivitiesReportCollaboratorJoined        *ActivitiesReportCollaboratorJoined        `json:"-"`
	ActivitiesReportSeverityUpdated           *ActivitiesReportSeverityUpdated           `json:"-"`
	ActivitiesReportTitleUpdated              *ActivitiesReportTitleUpdated              `json:"-"`
	ActivitiesReportVulnerabilityTypesUpdated *ActivitiesReportVulnerabilityTypesUpdated `json:"-"`
	ActivitiesSwagAwarded                     *ActivitiesSwagAwarded                     `json:"-"`
	ActivitiesTeamPublished                   *ActivitiesTeamPublished                   `json:"-"`
	ActivitiesUserAssignedToBug               *ActivitiesUserAssignedToBug               `json:"-"`
	ActivitiesUserBannedFromProgram           *ActivitiesUserBannedFromProgram           `json:"-"`
	ActivitiesUserCompletedRetest             *ActivitiesUserCompletedRetest             `json:"-"`
	ActivitiesUserJoined                      *ActivitiesUserJoined                      `json:"-"`
}

func (u *ActivityInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType ActivityInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "ActivitiesAgreedOnGoingPublic":
		u.ActivitiesAgreedOnGoingPublic = &ActivitiesAgreedOnGoingPublic{}
		payload = u.ActivitiesAgreedOnGoingPublic
	case "ActivitiesBountyAwarded":
		u.ActivitiesBountyAwarded = &ActivitiesBountyAwarded{}
		payload = u.ActivitiesBountyAwarded
	case "ActivitiesBountySuggested":
		u.ActivitiesBountySuggested = &ActivitiesBountySuggested{}
		payload = u.ActivitiesBountySuggested
	case "ActivitiesBugCloned":
		u.ActivitiesBugCloned = &ActivitiesBugCloned{}
		payload = u.ActivitiesBugCloned
	case "ActivitiesBugDuplicate":
		u.ActivitiesBugDuplicate = &ActivitiesBugDuplicate{}
		payload = u.ActivitiesBugDuplicate
	case "ActivitiesBugFiled":
		u.ActivitiesBugFiled = &ActivitiesBugFiled{}
		payload = u.ActivitiesBugFiled
	case "ActivitiesBugInactive":
		u.ActivitiesBugInactive = &ActivitiesBugInactive{}
		payload = u.ActivitiesBugInactive
	case "ActivitiesBugInformative":
		u.ActivitiesBugInformative = &ActivitiesBugInformative{}
		payload = u.ActivitiesBugInformative
	case "ActivitiesBugNeedsMoreInfo":
		u.ActivitiesBugNeedsMoreInfo = &ActivitiesBugNeedsMoreInfo{}
		payload = u.ActivitiesBugNeedsMoreInfo
	case "ActivitiesBugNew":
		u.ActivitiesBugNew = &ActivitiesBugNew{}
		payload = u.ActivitiesBugNew
	case "ActivitiesBugNotApplicable":
		u.ActivitiesBugNotApplicable = &ActivitiesBugNotApplicable{}
		payload = u.ActivitiesBugNotApplicable
	case "ActivitiesBugReopened":
		u.ActivitiesBugReopened = &ActivitiesBugReopened{}
		payload = u.ActivitiesBugReopened
	case "ActivitiesBugResolved":
		u.ActivitiesBugResolved = &ActivitiesBugResolved{}
		payload = u.ActivitiesBugResolved
	case "ActivitiesBugSpam":
		u.ActivitiesBugSpam = &ActivitiesBugSpam{}
		payload = u.ActivitiesBugSpam
	case "ActivitiesBugTriaged":
		u.ActivitiesBugTriaged = &ActivitiesBugTriaged{}
		payload = u.ActivitiesBugTriaged
	case "ActivitiesCancelledDisclosureRequest":
		u.ActivitiesCancelledDisclosureRequest = &ActivitiesCancelledDisclosureRequest{}
		payload = u.ActivitiesCancelledDisclosureRequest
	case "ActivitiesChangedScope":
		u.ActivitiesChangedScope = &ActivitiesChangedScope{}
		payload = u.ActivitiesChangedScope
	case "ActivitiesComment":
		u.ActivitiesComment = &ActivitiesComment{}
		payload = u.ActivitiesComment
	case "ActivitiesCommentsClosed":
		u.ActivitiesCommentsClosed = &ActivitiesCommentsClosed{}
		payload = u.ActivitiesCommentsClosed
	case "ActivitiesCVEIDAdded":
		u.ActivitiesCVEIDAdded = &ActivitiesCVEIDAdded{}
		payload = u.ActivitiesCVEIDAdded
	case "ActivitiesExternalAdvisoryAdded":
		u.ActivitiesExternalAdvisoryAdded = &ActivitiesExternalAdvisoryAdded{}
		payload = u.ActivitiesExternalAdvisoryAdded
	case "ActivitiesExternalUserInvitationCancelled":
		u.ActivitiesExternalUserInvitationCancelled = &ActivitiesExternalUserInvitationCancelled{}
		payload = u.ActivitiesExternalUserInvitationCancelled
	case "ActivitiesExternalUserInvited":
		u.ActivitiesExternalUserInvited = &ActivitiesExternalUserInvited{}
		payload = u.ActivitiesExternalUserInvited
	case "ActivitiesExternalUserJoined":
		u.ActivitiesExternalUserJoined = &ActivitiesExternalUserJoined{}
		payload = u.ActivitiesExternalUserJoined
	case "ActivitiesExternalUserRemoved":
		u.ActivitiesExternalUserRemoved = &ActivitiesExternalUserRemoved{}
		payload = u.ActivitiesExternalUserRemoved
	case "ActivitiesGroupAssignedToBug":
		u.ActivitiesGroupAssignedToBug = &ActivitiesGroupAssignedToBug{}
		payload = u.ActivitiesGroupAssignedToBug
	case "ActivitiesHackerRequestedMediation":
		u.ActivitiesHackerRequestedMediation = &ActivitiesHackerRequestedMediation{}
		payload = u.ActivitiesHackerRequestedMediation
	case "ActivitiesManuallyDisclosed":
		u.ActivitiesManuallyDisclosed = &ActivitiesManuallyDisclosed{}
		payload = u.ActivitiesManuallyDisclosed
	case "ActivitiesMediationRequested":
		u.ActivitiesMediationRequested = &ActivitiesMediationRequested{}
		payload = u.ActivitiesMediationRequested
	case "ActivitiesNobodyAssignedToBug":
		u.ActivitiesNobodyAssignedToBug = &ActivitiesNobodyAssignedToBug{}
		payload = u.ActivitiesNobodyAssignedToBug
	case "ActivitiesNotEligibleForBounty":
		u.ActivitiesNotEligibleForBounty = &ActivitiesNotEligibleForBounty{}
		payload = u.ActivitiesNotEligibleForBounty
	case "ActivitiesProgramInactive":
		u.ActivitiesProgramInactive = &ActivitiesProgramInactive{}
		payload = u.ActivitiesProgramInactive
	case "ActivitiesReassignedToTeam":
		u.ActivitiesReassignedToTeam = &ActivitiesReassignedToTeam{}
		payload = u.ActivitiesReassignedToTeam
	case "ActivitiesReferenceIDAdded":
		u.ActivitiesReferenceIDAdded = &ActivitiesReferenceIDAdded{}
		payload = u.ActivitiesReferenceIDAdded
	case "ActivitiesReportBecamePublic":
		u.ActivitiesReportBecamePublic = &ActivitiesReportBecamePublic{}
		payload = u.ActivitiesReportBecamePublic
	case "ActivitiesReportCollaboratorInvited":
		u.ActivitiesReportCollaboratorInvited = &ActivitiesReportCollaboratorInvited{}
		payload = u.ActivitiesReportCollaboratorInvited
	case "ActivitiesReportCollaboratorJoined":
		u.ActivitiesReportCollaboratorJoined = &ActivitiesReportCollaboratorJoined{}
		payload = u.ActivitiesReportCollaboratorJoined
	case "ActivitiesReportSeverityUpdated":
		u.ActivitiesReportSeverityUpdated = &ActivitiesReportSeverityUpdated{}
		payload = u.ActivitiesReportSeverityUpdated
	case "ActivitiesReportTitleUpdated":
		u.ActivitiesReportTitleUpdated = &ActivitiesReportTitleUpdated{}
		payload = u.ActivitiesReportTitleUpdated
	case "ActivitiesReportVulnerabilityTypesUpdated":
		u.ActivitiesReportVulnerabilityTypesUpdated = &ActivitiesReportVulnerabilityTypesUpdated{}
		payload = u.ActivitiesReportVulnerabilityTypesUpdated
	case "ActivitiesSwagAwarded":
		u.ActivitiesSwagAwarded = &ActivitiesSwagAwarded{}
		payload = u.ActivitiesSwagAwarded
	case "ActivitiesTeamPublished":
		u.ActivitiesTeamPublished = &ActivitiesTeamPublished{}
		payload = u.ActivitiesTeamPublished
	case "ActivitiesUserAssignedToBug":
		u.ActivitiesUserAssignedToBug = &ActivitiesUserAssignedToBug{}
		payload = u.ActivitiesUserAssignedToBug
	case "ActivitiesUserBannedFromProgram":
		u.ActivitiesUserBannedFromProgram = &ActivitiesUserBannedFromProgram{}
		payload = u.ActivitiesUserBannedFromProgram
	case "ActivitiesUserCompletedRetest":
		u.ActivitiesUserCompletedRetest = &ActivitiesUserCompletedRetest{}
		payload = u.ActivitiesUserCompletedRetest
	case "ActivitiesUserJoined":
		u.ActivitiesUserJoined = &ActivitiesUserJoined{}
		payload = u.ActivitiesUserJoined
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// The actor of an activity can be multiple types
type ActorUnion struct {
	TypeName__ string `json:"__typename,omitempty"`
	User       *User  `json:"-"`
	Team       *Team  `json:"-"`
}

func (u *ActorUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType ActorUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "User":
		u.User = &User{}
		payload = u.User
	case "Team":
		u.Team = &Team{}
		payload = u.Team
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A interface for the common fields on an HackerOne Report Activity
type ReportActivityInterface struct {
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID                         *string                                    `json:"genius_execution_id,omitempty"`
	Report                                    *Report                                    `json:"report,omitempty"`
	TypeName__                                string                                     `json:"__typename,omitempty"`
	ActivitiesAgreedOnGoingPublic             *ActivitiesAgreedOnGoingPublic             `json:"-"`
	ActivitiesBountyAwarded                   *ActivitiesBountyAwarded                   `json:"-"`
	ActivitiesBountySuggested                 *ActivitiesBountySuggested                 `json:"-"`
	ActivitiesBugCloned                       *ActivitiesBugCloned                       `json:"-"`
	ActivitiesBugDuplicate                    *ActivitiesBugDuplicate                    `json:"-"`
	ActivitiesBugFiled                        *ActivitiesBugFiled                        `json:"-"`
	ActivitiesBugInactive                     *ActivitiesBugInactive                     `json:"-"`
	ActivitiesBugInformative                  *ActivitiesBugInformative                  `json:"-"`
	ActivitiesBugNeedsMoreInfo                *ActivitiesBugNeedsMoreInfo                `json:"-"`
	ActivitiesBugNew                          *ActivitiesBugNew                          `json:"-"`
	ActivitiesBugNotApplicable                *ActivitiesBugNotApplicable                `json:"-"`
	ActivitiesBugReopened                     *ActivitiesBugReopened                     `json:"-"`
	ActivitiesBugResolved                     *ActivitiesBugResolved                     `json:"-"`
	ActivitiesBugSpam                         *ActivitiesBugSpam                         `json:"-"`
	ActivitiesBugTriaged                      *ActivitiesBugTriaged                      `json:"-"`
	ActivitiesCancelledDisclosureRequest      *ActivitiesCancelledDisclosureRequest      `json:"-"`
	ActivitiesChangedScope                    *ActivitiesChangedScope                    `json:"-"`
	ActivitiesComment                         *ActivitiesComment                         `json:"-"`
	ActivitiesCommentsClosed                  *ActivitiesCommentsClosed                  `json:"-"`
	ActivitiesCVEIDAdded                      *ActivitiesCVEIDAdded                      `json:"-"`
	ActivitiesExternalAdvisoryAdded           *ActivitiesExternalAdvisoryAdded           `json:"-"`
	ActivitiesExternalUserInvitationCancelled *ActivitiesExternalUserInvitationCancelled `json:"-"`
	ActivitiesExternalUserInvited             *ActivitiesExternalUserInvited             `json:"-"`
	ActivitiesExternalUserJoined              *ActivitiesExternalUserJoined              `json:"-"`
	ActivitiesExternalUserRemoved             *ActivitiesExternalUserRemoved             `json:"-"`
	ActivitiesGroupAssignedToBug              *ActivitiesGroupAssignedToBug              `json:"-"`
	ActivitiesHackerRequestedMediation        *ActivitiesHackerRequestedMediation        `json:"-"`
	ActivitiesManuallyDisclosed               *ActivitiesManuallyDisclosed               `json:"-"`
	ActivitiesMediationRequested              *ActivitiesMediationRequested              `json:"-"`
	ActivitiesNobodyAssignedToBug             *ActivitiesNobodyAssignedToBug             `json:"-"`
	ActivitiesNotEligibleForBounty            *ActivitiesNotEligibleForBounty            `json:"-"`
	ActivitiesProgramInactive                 *ActivitiesProgramInactive                 `json:"-"`
	ActivitiesReassignedToTeam                *ActivitiesReassignedToTeam                `json:"-"`
	ActivitiesReferenceIDAdded                *ActivitiesReferenceIDAdded                `json:"-"`
	ActivitiesReportBecamePublic              *ActivitiesReportBecamePublic              `json:"-"`
	ActivitiesReportCollaboratorInvited       *ActivitiesReportCollaboratorInvited       `json:"-"`
	ActivitiesReportCollaboratorJoined        *ActivitiesReportCollaboratorJoined        `json:"-"`
	ActivitiesReportSeverityUpdated           *ActivitiesReportSeverityUpdated           `json:"-"`
	ActivitiesReportTitleUpdated              *ActivitiesReportTitleUpdated              `json:"-"`
	ActivitiesReportVulnerabilityTypesUpdated *ActivitiesReportVulnerabilityTypesUpdated `json:"-"`
	ActivitiesSwagAwarded                     *ActivitiesSwagAwarded                     `json:"-"`
	ActivitiesUserAssignedToBug               *ActivitiesUserAssignedToBug               `json:"-"`
	ActivitiesUserBannedFromProgram           *ActivitiesUserBannedFromProgram           `json:"-"`
	ActivitiesUserCompletedRetest             *ActivitiesUserCompletedRetest             `json:"-"`
}

func (u *ReportActivityInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType ReportActivityInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "ActivitiesAgreedOnGoingPublic":
		u.ActivitiesAgreedOnGoingPublic = &ActivitiesAgreedOnGoingPublic{}
		payload = u.ActivitiesAgreedOnGoingPublic
	case "ActivitiesBountyAwarded":
		u.ActivitiesBountyAwarded = &ActivitiesBountyAwarded{}
		payload = u.ActivitiesBountyAwarded
	case "ActivitiesBountySuggested":
		u.ActivitiesBountySuggested = &ActivitiesBountySuggested{}
		payload = u.ActivitiesBountySuggested
	case "ActivitiesBugCloned":
		u.ActivitiesBugCloned = &ActivitiesBugCloned{}
		payload = u.ActivitiesBugCloned
	case "ActivitiesBugDuplicate":
		u.ActivitiesBugDuplicate = &ActivitiesBugDuplicate{}
		payload = u.ActivitiesBugDuplicate
	case "ActivitiesBugFiled":
		u.ActivitiesBugFiled = &ActivitiesBugFiled{}
		payload = u.ActivitiesBugFiled
	case "ActivitiesBugInactive":
		u.ActivitiesBugInactive = &ActivitiesBugInactive{}
		payload = u.ActivitiesBugInactive
	case "ActivitiesBugInformative":
		u.ActivitiesBugInformative = &ActivitiesBugInformative{}
		payload = u.ActivitiesBugInformative
	case "ActivitiesBugNeedsMoreInfo":
		u.ActivitiesBugNeedsMoreInfo = &ActivitiesBugNeedsMoreInfo{}
		payload = u.ActivitiesBugNeedsMoreInfo
	case "ActivitiesBugNew":
		u.ActivitiesBugNew = &ActivitiesBugNew{}
		payload = u.ActivitiesBugNew
	case "ActivitiesBugNotApplicable":
		u.ActivitiesBugNotApplicable = &ActivitiesBugNotApplicable{}
		payload = u.ActivitiesBugNotApplicable
	case "ActivitiesBugReopened":
		u.ActivitiesBugReopened = &ActivitiesBugReopened{}
		payload = u.ActivitiesBugReopened
	case "ActivitiesBugResolved":
		u.ActivitiesBugResolved = &ActivitiesBugResolved{}
		payload = u.ActivitiesBugResolved
	case "ActivitiesBugSpam":
		u.ActivitiesBugSpam = &ActivitiesBugSpam{}
		payload = u.ActivitiesBugSpam
	case "ActivitiesBugTriaged":
		u.ActivitiesBugTriaged = &ActivitiesBugTriaged{}
		payload = u.ActivitiesBugTriaged
	case "ActivitiesCancelledDisclosureRequest":
		u.ActivitiesCancelledDisclosureRequest = &ActivitiesCancelledDisclosureRequest{}
		payload = u.ActivitiesCancelledDisclosureRequest
	case "ActivitiesChangedScope":
		u.ActivitiesChangedScope = &ActivitiesChangedScope{}
		payload = u.ActivitiesChangedScope
	case "ActivitiesComment":
		u.ActivitiesComment = &ActivitiesComment{}
		payload = u.ActivitiesComment
	case "ActivitiesCommentsClosed":
		u.ActivitiesCommentsClosed = &ActivitiesCommentsClosed{}
		payload = u.ActivitiesCommentsClosed
	case "ActivitiesCVEIDAdded":
		u.ActivitiesCVEIDAdded = &ActivitiesCVEIDAdded{}
		payload = u.ActivitiesCVEIDAdded
	case "ActivitiesExternalAdvisoryAdded":
		u.ActivitiesExternalAdvisoryAdded = &ActivitiesExternalAdvisoryAdded{}
		payload = u.ActivitiesExternalAdvisoryAdded
	case "ActivitiesExternalUserInvitationCancelled":
		u.ActivitiesExternalUserInvitationCancelled = &ActivitiesExternalUserInvitationCancelled{}
		payload = u.ActivitiesExternalUserInvitationCancelled
	case "ActivitiesExternalUserInvited":
		u.ActivitiesExternalUserInvited = &ActivitiesExternalUserInvited{}
		payload = u.ActivitiesExternalUserInvited
	case "ActivitiesExternalUserJoined":
		u.ActivitiesExternalUserJoined = &ActivitiesExternalUserJoined{}
		payload = u.ActivitiesExternalUserJoined
	case "ActivitiesExternalUserRemoved":
		u.ActivitiesExternalUserRemoved = &ActivitiesExternalUserRemoved{}
		payload = u.ActivitiesExternalUserRemoved
	case "ActivitiesGroupAssignedToBug":
		u.ActivitiesGroupAssignedToBug = &ActivitiesGroupAssignedToBug{}
		payload = u.ActivitiesGroupAssignedToBug
	case "ActivitiesHackerRequestedMediation":
		u.ActivitiesHackerRequestedMediation = &ActivitiesHackerRequestedMediation{}
		payload = u.ActivitiesHackerRequestedMediation
	case "ActivitiesManuallyDisclosed":
		u.ActivitiesManuallyDisclosed = &ActivitiesManuallyDisclosed{}
		payload = u.ActivitiesManuallyDisclosed
	case "ActivitiesMediationRequested":
		u.ActivitiesMediationRequested = &ActivitiesMediationRequested{}
		payload = u.ActivitiesMediationRequested
	case "ActivitiesNobodyAssignedToBug":
		u.ActivitiesNobodyAssignedToBug = &ActivitiesNobodyAssignedToBug{}
		payload = u.ActivitiesNobodyAssignedToBug
	case "ActivitiesNotEligibleForBounty":
		u.ActivitiesNotEligibleForBounty = &ActivitiesNotEligibleForBounty{}
		payload = u.ActivitiesNotEligibleForBounty
	case "ActivitiesProgramInactive":
		u.ActivitiesProgramInactive = &ActivitiesProgramInactive{}
		payload = u.ActivitiesProgramInactive
	case "ActivitiesReassignedToTeam":
		u.ActivitiesReassignedToTeam = &ActivitiesReassignedToTeam{}
		payload = u.ActivitiesReassignedToTeam
	case "ActivitiesReferenceIDAdded":
		u.ActivitiesReferenceIDAdded = &ActivitiesReferenceIDAdded{}
		payload = u.ActivitiesReferenceIDAdded
	case "ActivitiesReportBecamePublic":
		u.ActivitiesReportBecamePublic = &ActivitiesReportBecamePublic{}
		payload = u.ActivitiesReportBecamePublic
	case "ActivitiesReportCollaboratorInvited":
		u.ActivitiesReportCollaboratorInvited = &ActivitiesReportCollaboratorInvited{}
		payload = u.ActivitiesReportCollaboratorInvited
	case "ActivitiesReportCollaboratorJoined":
		u.ActivitiesReportCollaboratorJoined = &ActivitiesReportCollaboratorJoined{}
		payload = u.ActivitiesReportCollaboratorJoined
	case "ActivitiesReportSeverityUpdated":
		u.ActivitiesReportSeverityUpdated = &ActivitiesReportSeverityUpdated{}
		payload = u.ActivitiesReportSeverityUpdated
	case "ActivitiesReportTitleUpdated":
		u.ActivitiesReportTitleUpdated = &ActivitiesReportTitleUpdated{}
		payload = u.ActivitiesReportTitleUpdated
	case "ActivitiesReportVulnerabilityTypesUpdated":
		u.ActivitiesReportVulnerabilityTypesUpdated = &ActivitiesReportVulnerabilityTypesUpdated{}
		payload = u.ActivitiesReportVulnerabilityTypesUpdated
	case "ActivitiesSwagAwarded":
		u.ActivitiesSwagAwarded = &ActivitiesSwagAwarded{}
		payload = u.ActivitiesSwagAwarded
	case "ActivitiesUserAssignedToBug":
		u.ActivitiesUserAssignedToBug = &ActivitiesUserAssignedToBug{}
		payload = u.ActivitiesUserAssignedToBug
	case "ActivitiesUserBannedFromProgram":
		u.ActivitiesUserBannedFromProgram = &ActivitiesUserBannedFromProgram{}
		payload = u.ActivitiesUserBannedFromProgram
	case "ActivitiesUserCompletedRetest":
		u.ActivitiesUserCompletedRetest = &ActivitiesUserCompletedRetest{}
		payload = u.ActivitiesUserCompletedRetest
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HackerOne report
type Report struct {
	ID_                              *string             `json:"_id,omitempty"`
	Activities                       *ActivityConnection `json:"activities,omitempty"`
	AllowSingularDisclosureAfter     *string             `json:"allow_singular_disclosure_after,omitempty"`
	AllowSingularDisclosureAt        *DateTime           `json:"allow_singular_disclosure_at,omitempty"`
	AncReasons                       []*string           `json:"anc_reasons,omitempty"`
	Assignee                         *AssigneeUnion      `json:"assignee,omitempty"`
	Attachments                      []*Attachment       `json:"attachments,omitempty"`
	Bounties                         []*Bounty           `json:"bounties,omitempty"`
	BountyAwardedAt                  *DateTime           `json:"bounty_awarded_at,omitempty"`
	BugReporterAgreedOnGoingPublicAt *DateTime           `json:"bug_reporter_agreed_on_going_public_at,omitempty"`
	ClonedFrom                       *Report             `json:"cloned_from,omitempty"`
	ClosedAt                         *DateTime           `json:"closed_at,omitempty"`
	CommentsClosed                   *bool               `json:"comments_closed,omitempty"`
	CreatedAt                        *DateTime           `json:"created_at,omitempty"`
	CVEIds                           []*string           `json:"cve_ids,omitempty"`
	DisclosedAt                      *DateTime           `json:"disclosed_at,omitempty"`
	FirstProgramActivityAt           *DateTime           `json:"first_program_activity_at,omitempty"`
	ICanAncReview                    *bool               `json:"i_can_anc_review,omitempty"`
	ID                               *string             `json:"id,omitempty"`
	LatestActivityAt                 *DateTime           `json:"latest_activity_at,omitempty"`
	LatestPublicActivityAt           *DateTime           `json:"latest_public_activity_at,omitempty"`
	LatestPublicActivityOfReporterAt *DateTime           `json:"latest_public_activity_of_reporter_at,omitempty"`
	LatestPublicActivityOfTeamAt     *DateTime           `json:"latest_public_activity_of_team_at,omitempty"`
	MediationRequestedAt             *DateTime           `json:"mediation_requested_at,omitempty"`
	OriginalReport                   *Report             `json:"original_report,omitempty"`
	// A post-submission trigger that notified the hacker after submission. This field is only present for reports filed after February 14, 2016.
	PostSubmissionTriggerLogTrigger *Trigger         `json:"post_submission_trigger_log_trigger,omitempty"`
	PreSubmissionReviewState        *string          `json:"pre_submission_review_state,omitempty"`
	PreviousSubstate                *string          `json:"previous_substate,omitempty"`
	Reference                       *string          `json:"reference,omitempty"`
	ReferenceLink                   *string          `json:"reference_link,omitempty"`
	Reporter                        *User            `json:"reporter,omitempty"`
	Severity                        *Severity        `json:"severity,omitempty"`
	SingularDisclosureAllowed       *bool            `json:"singular_disclosure_allowed,omitempty"`
	SingularDisclosureDisabled      *bool            `json:"singular_disclosure_disabled,omitempty"`
	SLAFailsInHours                 *int32           `json:"sla_fails_in_hours,omitempty"`
	Stage                           *string          `json:"stage,omitempty"`
	State                           *string          `json:"state,omitempty"`
	StructuredScope                 *StructuredScope `json:"structured_scope,omitempty"`
	Substate                        *string          `json:"substate,omitempty"`
	SuggestedBounty                 *string          `json:"suggested_bounty,omitempty"`
	Summaries                       []*Summary       `json:"summaries,omitempty"`
	Swag                            []*Swag          `json:"swag,omitempty"`
	SwagAwardedAt                   *DateTime        `json:"swag_awarded_at,omitempty"`
	Team                            *Team            `json:"team,omitempty"`
	TeamMemberAgreedOnGoingPublicAt *DateTime        `json:"team_member_agreed_on_going_public_at,omitempty"`
	Title                           *string          `json:"title,omitempty"`
	TriageMeta                      *TriageMeta      `json:"triage_meta,omitempty"`
	TriagedAt                       *DateTime        `json:"triaged_at,omitempty"`
	URL                             *URI             `json:"url,omitempty"`
	Votes                           *VoteConnection  `json:"votes,omitempty"`
	VulnerabilityInformation        *string          `json:"vulnerability_information,omitempty"`
	VulnerabilityInformationHtml    *string          `json:"vulnerability_information_html,omitempty"`
	Weakness                        *Weakness        `json:"weakness,omitempty"`
}

// Report can be assigned to either a user or a team member group
type AssigneeUnion struct {
	TypeName__      string           `json:"__typename,omitempty"`
	User            *User            `json:"-"`
	TeamMemberGroup *TeamMemberGroup `json:"-"`
}

func (u *AssigneeUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType AssigneeUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "User":
		u.User = &User{}
		payload = u.User
	case "TeamMemberGroup":
		u.TeamMemberGroup = &TeamMemberGroup{}
		payload = u.TeamMemberGroup
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HackerOne team member group
type TeamMemberGroup struct {
	ID_         *string       `json:"_id,omitempty"`
	CreatedAt   *DateTime     `json:"created_at,omitempty"`
	ID          *string       `json:"id,omitempty"`
	Immutable   *bool         `json:"immutable,omitempty"`
	Key         *string       `json:"key,omitempty"`
	Name        *string       `json:"name,omitempty"`
	Permissions []*string     `json:"permissions,omitempty"`
	TeamMembers []*TeamMember `json:"team_members,omitempty"`
}

// A HackerOne severity for a report
type Severity struct {
	ID_                *string                         `json:"_id,omitempty"`
	AttackComplexity   *SeverityAttackComplexityEnum   `json:"attack_complexity,omitempty"`
	AttackVector       *SeverityAttackVectorEnum       `json:"attack_vector,omitempty"`
	AuthorType         *SeverityAuthorEnum             `json:"author_type,omitempty"`
	Availability       *SeverityAvailabilityEnum       `json:"availability,omitempty"`
	Confidentiality    *SeverityConfidentialityEnum    `json:"confidentiality,omitempty"`
	CreatedAt          *DateTime                       `json:"created_at,omitempty"`
	ID                 *string                         `json:"id,omitempty"`
	Integrity          *SeverityIntegrityEnum          `json:"integrity,omitempty"`
	PrivilegesRequired *SeverityPrivilegesRequiredEnum `json:"privileges_required,omitempty"`
	Rating             *SeverityRatingEnum             `json:"rating,omitempty"`
	Scope              *SeverityScopeEnum              `json:"scope,omitempty"`
	Score              *float64                        `json:"score,omitempty"`
	UserID             *int32                          `json:"user_id,omitempty"`
	UserInteraction    *SeverityUserInteractionEnum    `json:"user_interaction,omitempty"`
}

// Severity author
type SeverityAuthorEnum string

const (
	SeverityAuthorEnumUser SeverityAuthorEnum = "User"
	SeverityAuthorEnumTeam SeverityAuthorEnum = "Team"
)

// Severity attack complexity
type SeverityAttackComplexityEnum string

const (
	SeverityAttackComplexityEnumLow  SeverityAttackComplexityEnum = "low"
	SeverityAttackComplexityEnumHigh SeverityAttackComplexityEnum = "high"
)

// Severity attack vector
type SeverityAttackVectorEnum string

const (
	SeverityAttackVectorEnumNetwork  SeverityAttackVectorEnum = "network"
	SeverityAttackVectorEnumAdjacent SeverityAttackVectorEnum = "adjacent"
	SeverityAttackVectorEnumLocal    SeverityAttackVectorEnum = "local"
	SeverityAttackVectorEnumPhysical SeverityAttackVectorEnum = "physical"
)

// Severity availability
type SeverityAvailabilityEnum string

const (
	SeverityAvailabilityEnumNone SeverityAvailabilityEnum = "none"
	SeverityAvailabilityEnumLow  SeverityAvailabilityEnum = "low"
	SeverityAvailabilityEnumHigh SeverityAvailabilityEnum = "high"
)

// Severity confidentiality
type SeverityConfidentialityEnum string

const (
	SeverityConfidentialityEnumNone SeverityConfidentialityEnum = "none"
	SeverityConfidentialityEnumLow  SeverityConfidentialityEnum = "low"
	SeverityConfidentialityEnumHigh SeverityConfidentialityEnum = "high"
)

// Severity integrity
type SeverityIntegrityEnum string

const (
	SeverityIntegrityEnumNone SeverityIntegrityEnum = "none"
	SeverityIntegrityEnumLow  SeverityIntegrityEnum = "low"
	SeverityIntegrityEnumHigh SeverityIntegrityEnum = "high"
)

// Severity privileges required
type SeverityPrivilegesRequiredEnum string

const (
	SeverityPrivilegesRequiredEnumNone SeverityPrivilegesRequiredEnum = "none"
	SeverityPrivilegesRequiredEnumLow  SeverityPrivilegesRequiredEnum = "low"
	SeverityPrivilegesRequiredEnumHigh SeverityPrivilegesRequiredEnum = "high"
)

// Severity user interaction
type SeverityUserInteractionEnum string

const (
	SeverityUserInteractionEnumNone     SeverityUserInteractionEnum = "none"
	SeverityUserInteractionEnumRequired SeverityUserInteractionEnum = "required"
)

// Severity scope
type SeverityScopeEnum string

const (
	SeverityScopeEnumUnchanged SeverityScopeEnum = "unchanged"
	SeverityScopeEnumChanged   SeverityScopeEnum = "changed"
)

// Triage meta
type TriageMeta struct {
	AssignedTriager *User   `json:"assigned_triager,omitempty"`
	ID              *string `json:"id,omitempty"`
	URL             *URI    `json:"url,omitempty"`
}

// A defined scope of a HackerOne program
type StructuredScope struct {
	ID_                                  *string                           `json:"_id,omitempty"`
	ArchivedAt                           *DateTime                         `json:"archived_at,omitempty"`
	AssetIdentifier                      *string                           `json:"asset_identifier,omitempty"`
	AssetType                            *StructuredScopeAssetTypeEnum     `json:"asset_type,omitempty"`
	AvailabilityRequirement              *SeveritySecurityRequirementEnum  `json:"availability_requirement,omitempty"`
	ConfidentialityRequirement           *SeveritySecurityRequirementEnum  `json:"confidentiality_requirement,omitempty"`
	CreatedAt                            *DateTime                         `json:"created_at,omitempty"`
	CriticalSeverityResolvedReportsCount *int32                            `json:"critical_severity_resolved_reports_count,omitempty"`
	EligibleForBounty                    *bool                             `json:"eligible_for_bounty,omitempty"`
	EligibleForSubmission                *bool                             `json:"eligible_for_submission,omitempty"`
	HighSeverityResolvedReportsCount     *int32                            `json:"high_severity_resolved_reports_count,omitempty"`
	ID                                   *string                           `json:"id,omitempty"`
	Instruction                          *string                           `json:"instruction,omitempty"`
	IntegrityRequirement                 *SeveritySecurityRequirementEnum  `json:"integrity_requirement,omitempty"`
	LowSeverityResolvedReportsCount      *int32                            `json:"low_severity_resolved_reports_count,omitempty"`
	MaxSeverity                          *SeverityRatingEnum               `json:"max_severity,omitempty"`
	MediumSeverityResolvedReportsCount   *int32                            `json:"medium_severity_resolved_reports_count,omitempty"`
	Reference                            *string                           `json:"reference,omitempty"`
	RenderedInstruction                  *string                           `json:"rendered_instruction,omitempty"`
	Reports                              *ReportConnection                 `json:"reports,omitempty"`
	StructuredScopeVersions              *StructuredScopeVersionConnection `json:"structured_scope_versions,omitempty"`
	Team                                 *Team                             `json:"team,omitempty"`
	UpdatedAt                            *DateTime                         `json:"updated_at,omitempty"`
	URL                                  *URI                              `json:"url,omitempty"`
}

// Severity security requirement rating
type SeveritySecurityRequirementEnum string

const (
	SeveritySecurityRequirementEnumNone   SeveritySecurityRequirementEnum = "none"
	SeveritySecurityRequirementEnumLow    SeveritySecurityRequirementEnum = "low"
	SeveritySecurityRequirementEnumMedium SeveritySecurityRequirementEnum = "medium"
	SeveritySecurityRequirementEnumHigh   SeveritySecurityRequirementEnum = "high"
)

// The connection type for StructuredScopeVersion.
type StructuredScopeVersionConnection struct {
	// A list of edges.
	Edges        []*StructuredScopeVersionEdge `json:"edges,omitempty"`
	MaxUpdatedAt *DateTime                     `json:"max_updated_at,omitempty"`
	// A list of nodes.
	Nodes []*StructuredScopeVersion `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type StructuredScopeVersionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *StructuredScopeVersion `json:"node,omitempty"`
}

// A versioned log of a scope of a HackerOne program
type StructuredScopeVersion struct {
	ID_         *string   `json:"_id,omitempty"`
	ArchivedAt  *DateTime `json:"archived_at,omitempty"`
	CreatedAt   *DateTime `json:"created_at,omitempty"`
	ID          *string   `json:"id,omitempty"`
	Instruction *string   `json:"instruction,omitempty"`
	MaxSeverity *string   `json:"max_severity,omitempty"`
	Team        *Team     `json:"team,omitempty"`
	URL         *URI      `json:"url,omitempty"`
}

// The connection type for Report.
type ReportConnection struct {
	// Groups and counts reports by the severity rating
	CountBySeverity []*int32 `json:"count_by_severity,omitempty"`
	// A list of edges.
	Edges []*ReportEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Report `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// An edge in a connection.
type ReportEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Report `json:"node,omitempty"`
}

type FiltersReportFilterInput struct {
	Or_                      []*FiltersReportFilterInput    `json:"_or,omitempty"`
	And_                     []*FiltersReportFilterInput    `json:"_and,omitempty"`
	ID                       *IntPredicateInput             `json:"id,omitempty"`
	Title                    *StringPredicateInput          `json:"title,omitempty"`
	VulnerabilityInformation *StringPredicateInput          `json:"vulnerability_information,omitempty"`
	Substate                 *ReportStateEnumPredicateInput `json:"substate,omitempty"`
	IneligibleForBounty      *BooleanPredicateInput         `json:"ineligible_for_bounty,omitempty"`
	HackerPublished          *BooleanPredicateInput         `json:"hacker_published,omitempty"`
	DisclosedAt              *DateTimePredicateInput        `json:"disclosed_at,omitempty"`
	BountyAwardedAt          *DateTimePredicateInput        `json:"bounty_awarded_at,omitempty"`
	ClosedAt                 *DateTimePredicateInput        `json:"closed_at,omitempty"`
	Team                     *FiltersTeamFilterInput        `json:"team,omitempty"`
	Weakness                 *FiltersWeaknessFilterInput    `json:"weakness,omitempty"`
}

type ReportStateEnumPredicateInput struct {
	Eq_     *ReportStateEnum   `json:"_eq,omitempty"`
	Neq_    *ReportStateEnum   `json:"_neq,omitempty"`
	Gt_     *ReportStateEnum   `json:"_gt,omitempty"`
	Lt_     *ReportStateEnum   `json:"_lt,omitempty"`
	Gte_    *ReportStateEnum   `json:"_gte,omitempty"`
	Lte_    *ReportStateEnum   `json:"_lte,omitempty"`
	In_     []*ReportStateEnum `json:"_in,omitempty"`
	Nin_    []*ReportStateEnum `json:"_nin,omitempty"`
	IsNull_ *bool              `json:"_is_null,omitempty"`
}

// States a report can be in
type ReportStateEnum string

const (
	ReportStateEnumNew           ReportStateEnum = "new"
	ReportStateEnumTriaged       ReportStateEnum = "triaged"
	ReportStateEnumNeedsMoreInfo ReportStateEnum = "needs_more_info"
	ReportStateEnumResolved      ReportStateEnum = "resolved"
	ReportStateEnumInformative   ReportStateEnum = "informative"
	ReportStateEnumNotApplicable ReportStateEnum = "not_applicable"
	ReportStateEnumDuplicate     ReportStateEnum = "duplicate"
	ReportStateEnumSpam          ReportStateEnum = "spam"
	ReportStateEnumOpen          ReportStateEnum = "open"
	ReportStateEnumClosed        ReportStateEnum = "closed"
	ReportStateEnumPreSubmission ReportStateEnum = "pre_submission"
)

type DateTimePredicateInput struct {
	Eq_     *DateTime   `json:"_eq,omitempty"`
	Neq_    *DateTime   `json:"_neq,omitempty"`
	Gt_     *DateTime   `json:"_gt,omitempty"`
	Lt_     *DateTime   `json:"_lt,omitempty"`
	Gte_    *DateTime   `json:"_gte,omitempty"`
	Lte_    *DateTime   `json:"_lte,omitempty"`
	In_     []*DateTime `json:"_in,omitempty"`
	Nin_    []*DateTime `json:"_nin,omitempty"`
	IsNull_ *bool       `json:"_is_null,omitempty"`
}

type FiltersWeaknessFilterInput struct {
	Or_  []*FiltersWeaknessFilterInput `json:"_or,omitempty"`
	And_ []*FiltersWeaknessFilterInput `json:"_and,omitempty"`
	ID   *IntPredicateInput            `json:"id,omitempty"`
	Name *StringPredicateInput         `json:"name,omitempty"`
}

// Pre submission review states a report can be in
type ReportPreSubmissionReviewStateEnum string

const (
	ReportPreSubmissionReviewStateEnumPreSubmissionPending       ReportPreSubmissionReviewStateEnum = "pre_submission_pending"
	ReportPreSubmissionReviewStateEnumPreSubmissionAccepted      ReportPreSubmissionReviewStateEnum = "pre_submission_accepted"
	ReportPreSubmissionReviewStateEnumPreSubmissionRejected      ReportPreSubmissionReviewStateEnum = "pre_submission_rejected"
	ReportPreSubmissionReviewStateEnumPreSubmissionNeedsMoreInfo ReportPreSubmissionReviewStateEnum = "pre_submission_needs_more_info"
)

type ReportOrderInput struct {
	Direction *OrderDirection   `json:"direction,omitempty"`
	Field     *ReportOrderField `json:"field,omitempty"`
}

// Fields on which a collection of reports can be ordered
type ReportOrderField string

const (
	ReportOrderFieldID                     ReportOrderField = "id"
	ReportOrderFieldCreatedAt              ReportOrderField = "created_at"
	ReportOrderFieldLatestActivityAt       ReportOrderField = "latest_activity_at"
	ReportOrderFieldSLAFailsAt             ReportOrderField = "sla_fails_at"
	ReportOrderFieldSwagAwardedAt          ReportOrderField = "swag_awarded_at"
	ReportOrderFieldBountyAwardedAt        ReportOrderField = "bounty_awarded_at"
	ReportOrderFieldLastReporterActivityAt ReportOrderField = "last_reporter_activity_at"
	ReportOrderFieldFirstProgramActivityAt ReportOrderField = "first_program_activity_at"
	ReportOrderFieldLastProgramActivityAt  ReportOrderField = "last_program_activity_at"
	ReportOrderFieldLastPublicActivityAt   ReportOrderField = "last_public_activity_at"
	ReportOrderFieldLastActivityAt         ReportOrderField = "last_activity_at"
	ReportOrderFieldTriagedAt              ReportOrderField = "triaged_at"
	ReportOrderFieldClosedAt               ReportOrderField = "closed_at"
	ReportOrderFieldDisclosedAt            ReportOrderField = "disclosed_at"
)

type FiltersReportFilterOrder struct {
	Field     *FiltersReportFilterOrderField `json:"field,omitempty"`
	Direction *FilterOrderDirectionEnum      `json:"direction,omitempty"`
}

type FiltersReportFilterOrderField string

const (
	FiltersReportFilterOrderFieldID FiltersReportFilterOrderField = "id"
)

type ReportFilterInput struct {
	Program                    []*string          `json:"program,omitempty"`
	Reporter                   []*string          `json:"reporter,omitempty"`
	Assignee                   []*string          `json:"assignee,omitempty"`
	State                      []*ReportStateEnum `json:"state,omitempty"`
	ID                         []*int32           `json:"id,omitempty"`
	CreatedAtGt                *DateTime          `json:"created_at__gt,omitempty"`
	CreatedAtLt                *DateTime          `json:"created_at__lt,omitempty"`
	TriagedAtGt                *DateTime          `json:"triaged_at__gt,omitempty"`
	TriagedAtLt                *DateTime          `json:"triaged_at__lt,omitempty"`
	TriagedAtNull              *bool              `json:"triaged_at__null,omitempty"`
	ClosedAtGt                 *DateTime          `json:"closed_at__gt,omitempty"`
	ClosedAtLt                 *DateTime          `json:"closed_at__lt,omitempty"`
	ClosedAtNull               *bool              `json:"closed_at__null,omitempty"`
	DisclosedAtGt              *DateTime          `json:"disclosed_at__gt,omitempty"`
	DisclosedAtLt              *DateTime          `json:"disclosed_at__lt,omitempty"`
	DisclosedAtNull            *bool              `json:"disclosed_at__null,omitempty"`
	BountyAwardedAtGt          *DateTime          `json:"bounty_awarded_at__gt,omitempty"`
	BountyAwardedAtLt          *DateTime          `json:"bounty_awarded_at__lt,omitempty"`
	BountyAwardedAtNull        *bool              `json:"bounty_awarded_at__null,omitempty"`
	SwagAwardedAtGt            *DateTime          `json:"swag_awarded_at__gt,omitempty"`
	SwagAwardedAtLt            *DateTime          `json:"swag_awarded_at__lt,omitempty"`
	SwagAwardedAtNull          *bool              `json:"swag_awarded_at__null,omitempty"`
	LastReporterActivityAtGt   *DateTime          `json:"last_reporter_activity_at__gt,omitempty"`
	LastReporterActivityAtLt   *DateTime          `json:"last_reporter_activity_at__lt,omitempty"`
	FirstProgramActivityAtGt   *DateTime          `json:"first_program_activity_at__gt,omitempty"`
	FirstProgramActivityAtLt   *DateTime          `json:"first_program_activity_at__lt,omitempty"`
	FirstProgramActivityAtNull *bool              `json:"first_program_activity_at__null,omitempty"`
	LastProgramActivityAtGt    *DateTime          `json:"last_program_activity_at__gt,omitempty"`
	LastProgramActivityAtLt    *DateTime          `json:"last_program_activity_at__lt,omitempty"`
	LastActivityAtGt           *DateTime          `json:"last_activity_at__gt,omitempty"`
	LastActivityAtLt           *DateTime          `json:"last_activity_at__lt,omitempty"`
	LastPublicActivityAtGt     *DateTime          `json:"last_public_activity_at__gt,omitempty"`
	LastPublicActivityAtLt     *DateTime          `json:"last_public_activity_at__lt,omitempty"`
}

// A HackerOne swag awarded for a report
type Swag struct {
	ID_       *string   `json:"_id,omitempty"`
	CreatedAt *DateTime `json:"created_at,omitempty"`
	ID        *string   `json:"id,omitempty"`
	Report    *Report   `json:"report,omitempty"`
	Sent      *bool     `json:"sent,omitempty"`
	Team      *Team     `json:"team,omitempty"`
	User      *User     `json:"user,omitempty"`
}

// A HackerOne attachment for a report
type Attachment struct {
	ID_         *string   `json:"_id,omitempty"`
	ContentType *string   `json:"content_type,omitempty"`
	CreatedAt   *DateTime `json:"created_at,omitempty"`
	ExpiringURL *string   `json:"expiring_url,omitempty"`
	FileName    *string   `json:"file_name,omitempty"`
	FileSize    *int32    `json:"file_size,omitempty"`
	ID          *string   `json:"id,omitempty"`
}

// A HackerOne bounty for a report
type Bounty struct {
	ID_                *string           `json:"_id,omitempty"`
	Amount             *string           `json:"amount,omitempty"`
	AwardedAmount      *string           `json:"awarded_amount,omitempty"`
	AwardedBonusAmount *string           `json:"awarded_bonus_amount,omitempty"`
	AwardedCurrency    *string           `json:"awarded_currency,omitempty"`
	BonusAmount        *string           `json:"bonus_amount,omitempty"`
	CreatedAt          *DateTime         `json:"created_at,omitempty"`
	ID                 *string           `json:"id,omitempty"`
	Report             *Report           `json:"report,omitempty"`
	Status             *BountyStatusEnum `json:"status,omitempty"`
}

// Status which reflect the state of a bounty
type BountyStatusEnum string

const (
	BountyStatusEnumNoTaxForm         BountyStatusEnum = "no_tax_form"
	BountyStatusEnumNoStatus          BountyStatusEnum = "no_status"
	BountyStatusEnumNeedsPayoutMethod BountyStatusEnum = "needs_payout_method"
	BountyStatusEnumNeedsTaxForm      BountyStatusEnum = "needs_tax_form"
	BountyStatusEnumPendingOfacCheck  BountyStatusEnum = "pending_ofac_check"
	BountyStatusEnumFailedOfacCheck   BountyStatusEnum = "failed_ofac_check"
	BountyStatusEnumOfacReject        BountyStatusEnum = "ofac_reject"
	BountyStatusEnumPending           BountyStatusEnum = "pending"
	BountyStatusEnumSent              BountyStatusEnum = "sent"
	BountyStatusEnumConfirmed         BountyStatusEnum = "confirmed"
	BountyStatusEnumRejected          BountyStatusEnum = "rejected"
	BountyStatusEnumCancelled         BountyStatusEnum = "cancelled"
	BountyStatusEnumFailed            BountyStatusEnum = "failed"
	BountyStatusEnumHold              BountyStatusEnum = "hold"
	BountyStatusEnumNoMileageAccount  BountyStatusEnum = "no_mileage_account"
	BountyStatusEnumExternalPayment   BountyStatusEnum = "external_payment"
)

// A HackerOne summary for a report
type Summary struct {
	ID_ *string `json:"_id,omitempty"`
	// DEPRECATED: The implementation of this field contains hard to reason about polymorphism
	Category  *string   `json:"category,omitempty"`
	Content   *string   `json:"content,omitempty"`
	CreatedAt *DateTime `json:"created_at,omitempty"`
	ID        *string   `json:"id,omitempty"`
	UpdatedAt *DateTime `json:"updated_at,omitempty"`
	User      *User     `json:"user,omitempty"`
}

// Trigger
type Trigger struct {
	ID_                *string               `json:"_id,omitempty"`
	ActionMessage      *string               `json:"action_message,omitempty"`
	ActionType         *string               `json:"action_type,omitempty"`
	CreatedAt          *DateTime             `json:"created_at,omitempty"`
	ExpressionOperator *string               `json:"expression_operator,omitempty"`
	Expressions        *ExpressionConnection `json:"expressions,omitempty"`
	ID                 *string               `json:"id,omitempty"`
	Seeded             *bool                 `json:"seeded,omitempty"`
	Team               *Team                 `json:"team,omitempty"`
	// DEPRECATED: It won't be used when new triggers launched
	Title             *string                     `json:"title,omitempty"`
	TriggerActionLogs *TriggerActionLogConnection `json:"trigger_action_logs,omitempty"`
	URL               *URI                        `json:"url,omitempty"`
}

// The connection type for Expression.
type ExpressionConnection struct {
	// A list of edges.
	Edges []*ExpressionEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Expression `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type ExpressionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Expression `json:"node,omitempty"`
}

// Trigger Expression
type Expression struct {
	ID_        *string  `json:"_id,omitempty"`
	ID         *string  `json:"id,omitempty"`
	LeftValue  *string  `json:"left_value,omitempty"`
	Operand    *string  `json:"operand,omitempty"`
	RightValue *string  `json:"right_value,omitempty"`
	Trigger    *Trigger `json:"trigger,omitempty"`
}

// The connection type for TriggerActionLog.
type TriggerActionLogConnection struct {
	// A list of edges.
	Edges []*TriggerActionLogEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*TriggerActionLog `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TriggerActionLogEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *TriggerActionLog `json:"node,omitempty"`
}

// TriggerActionLog
type TriggerActionLog struct {
	ID_ *string `json:"_id,omitempty"`
	ID  *string `json:"id,omitempty"`
}

type ActivityOrderInput struct {
	Direction *OrderDirection     `json:"direction,omitempty"`
	Field     *ActivityOrderField `json:"field,omitempty"`
}

// Fields on which a collection of activities can be ordered
type ActivityOrderField string

const (
	ActivityOrderFieldCreatedAt ActivityOrderField = "created_at"
	ActivityOrderFieldUpdatedAt ActivityOrderField = "updated_at"
)

// Possible types for an activity
type ActivityTypes string

const (
	ActivityTypesAgreedOnGoingPublic             ActivityTypes = "AgreedOnGoingPublic"
	ActivityTypesBountyAwarded                   ActivityTypes = "BountyAwarded"
	ActivityTypesBountySuggested                 ActivityTypes = "BountySuggested"
	ActivityTypesBugCloned                       ActivityTypes = "BugCloned"
	ActivityTypesBugDuplicate                    ActivityTypes = "BugDuplicate"
	ActivityTypesBugInformative                  ActivityTypes = "BugInformative"
	ActivityTypesBugNeedsMoreInfo                ActivityTypes = "BugNeedsMoreInfo"
	ActivityTypesBugNew                          ActivityTypes = "BugNew"
	ActivityTypesBugNotApplicable                ActivityTypes = "BugNotApplicable"
	ActivityTypesBugInactive                     ActivityTypes = "BugInactive"
	ActivityTypesBugReopened                     ActivityTypes = "BugReopened"
	ActivityTypesBugResolved                     ActivityTypes = "BugResolved"
	ActivityTypesBugSpam                         ActivityTypes = "BugSpam"
	ActivityTypesBugTriaged                      ActivityTypes = "BugTriaged"
	ActivityTypesBugFiled                        ActivityTypes = "BugFiled"
	ActivityTypesCancelledDisclosureRequest      ActivityTypes = "CancelledDisclosureRequest"
	ActivityTypesChangedScope                    ActivityTypes = "ChangedScope"
	ActivityTypesComment                         ActivityTypes = "Comment"
	ActivityTypesCommentsClosed                  ActivityTypes = "CommentsClosed"
	ActivityTypesExternalUserInvitationCancelled ActivityTypes = "ExternalUserInvitationCancelled"
	ActivityTypesExternalAdvisoryAdded           ActivityTypes = "ExternalAdvisoryAdded"
	ActivityTypesExternalUserInvited             ActivityTypes = "ExternalUserInvited"
	ActivityTypesExternalUserJoined              ActivityTypes = "ExternalUserJoined"
	ActivityTypesExternalUserRemoved             ActivityTypes = "ExternalUserRemoved"
	ActivityTypesGroupAssignedToBug              ActivityTypes = "GroupAssignedToBug"
	ActivityTypesHackerRequestedMediation        ActivityTypes = "HackerRequestedMediation"
	ActivityTypesManuallyDisclosed               ActivityTypes = "ManuallyDisclosed"
	ActivityTypesMediationRequested              ActivityTypes = "MediationRequested"
	ActivityTypesNotEligibleForBounty            ActivityTypes = "NotEligibleForBounty"
	ActivityTypesReferenceIDAdded                ActivityTypes = "ReferenceIdAdded"
	ActivityTypesCVEIDAdded                      ActivityTypes = "CveIdAdded"
	ActivityTypesReassignedToTeam                ActivityTypes = "ReassignedToTeam"
	ActivityTypesReportBecamePublic              ActivityTypes = "ReportBecamePublic"
	ActivityTypesReportTitleUpdated              ActivityTypes = "ReportTitleUpdated"
	ActivityTypesReportVulnerabilityTypesUpdated ActivityTypes = "ReportVulnerabilityTypesUpdated"
	ActivityTypesReportSeverityUpdated           ActivityTypes = "ReportSeverityUpdated"
	ActivityTypesReportCollaboratorInvited       ActivityTypes = "ReportCollaboratorInvited"
	ActivityTypesReportCollaboratorJoined        ActivityTypes = "ReportCollaboratorJoined"
	ActivityTypesSwagAwarded                     ActivityTypes = "SwagAwarded"
	ActivityTypesTeamPublished                   ActivityTypes = "TeamPublished"
	ActivityTypesUserAssignedToBug               ActivityTypes = "UserAssignedToBug"
	ActivityTypesUserBannedFromProgram           ActivityTypes = "UserBannedFromProgram"
	ActivityTypesUserJoined                      ActivityTypes = "UserJoined"
	ActivityTypesNobodyAssignedToBug             ActivityTypes = "NobodyAssignedToBug"
	ActivityTypesProgramInactive                 ActivityTypes = "ProgramInactive"
	ActivityTypesUserCompletedRetest             ActivityTypes = "UserCompletedRetest"
)

// The connection type for Vote.
type VoteConnection struct {
	// A list of edges.
	Edges []*VoteEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Vote `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// An edge in a connection.
type VoteEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Vote `json:"node,omitempty"`
}

// A Vote for a hacktivity item
type Vote struct {
	// The primary key from the database
	ID_    *string `json:"_id,omitempty"`
	ID     *string `json:"id,omitempty"`
	Report *Report `json:"report,omitempty"`
	User   *User   `json:"user,omitempty"`
}

// A Activities::BountyAwarded activity for a report
type ActivitiesBountyAwarded struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	BonusAmount       *string       `json:"bonus_amount,omitempty"`
	BountyAmount      *string       `json:"bounty_amount,omitempty"`
	BountyCurrency    *string       `json:"bounty_currency,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BountySuggested activity for a report
type ActivitiesBountySuggested struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	BonusAmount       *string       `json:"bonus_amount,omitempty"`
	BountyAmount      *string       `json:"bounty_amount,omitempty"`
	BountyCurrency    *string       `json:"bounty_currency,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugCloned activity for a report
type ActivitiesBugCloned struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool   `json:"i_can_edit,omitempty"`
	ID                *string `json:"id,omitempty"`
	Internal          *bool   `json:"internal,omitempty"`
	MarkdownMessage   *string `json:"markdown_message,omitempty"`
	Message           *string `json:"message,omitempty"`
	OriginalReport    *Report `json:"original_report,omitempty"`
	// DEPRECATED: Deprecated in favor of .original_report
	OriginalReportID *int32    `json:"original_report_id,omitempty"`
	Report           *Report   `json:"report,omitempty"`
	UpdatedAt        *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugDuplicate activity for a report
type ActivitiesBugDuplicate struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool   `json:"i_can_edit,omitempty"`
	ID                *string `json:"id,omitempty"`
	Internal          *bool   `json:"internal,omitempty"`
	MarkdownMessage   *string `json:"markdown_message,omitempty"`
	Message           *string `json:"message,omitempty"`
	OriginalReport    *Report `json:"original_report,omitempty"`
	// DEPRECATED: Deprecated in favor of .original_report
	OriginalReportID *int32    `json:"original_report_id,omitempty"`
	Report           *Report   `json:"report,omitempty"`
	UpdatedAt        *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugInformative activity for a report
type ActivitiesBugInformative struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugNeedsMoreInfo activity for a report
type ActivitiesBugNeedsMoreInfo struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugNew activity for a report
type ActivitiesBugNew struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugNotApplicable activity for a report
type ActivitiesBugNotApplicable struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugInactive activity for a report
type ActivitiesBugInactive struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugReopened activity for a report
type ActivitiesBugReopened struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugResolved activity for a report
type ActivitiesBugResolved struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugSpam activity for a report
type ActivitiesBugSpam struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugTriaged activity for a report
type ActivitiesBugTriaged struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::BugFiled activity for a report
type ActivitiesBugFiled struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::CancelledDisclosureRequest activity for a report
type ActivitiesCancelledDisclosureRequest struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ChangedScope activity for a report
type ActivitiesChangedScope struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string          `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool            `json:"i_can_edit,omitempty"`
	ID                *string          `json:"id,omitempty"`
	Internal          *bool            `json:"internal,omitempty"`
	MarkdownMessage   *string          `json:"markdown_message,omitempty"`
	Message           *string          `json:"message,omitempty"`
	NewScope          *StructuredScope `json:"new_scope,omitempty"`
	OldScope          *StructuredScope `json:"old_scope,omitempty"`
	Report            *Report          `json:"report,omitempty"`
	UpdatedAt         *DateTime        `json:"updated_at,omitempty"`
}

// A Activities::Comment activity for a report
type ActivitiesComment struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::CommentsClosed activity for a report
type ActivitiesCommentsClosed struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ExternalUserInvitationCancelled activity for a report
type ActivitiesExternalUserInvitationCancelled struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	Email             *string       `json:"email,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ExternalAdvisoryAdded activity for a report
type ActivitiesExternalAdvisoryAdded struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ExternalUserInvited activity for a report
type ActivitiesExternalUserInvited struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	Email             *string       `json:"email,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ExternalUserJoined activity for a report
type ActivitiesExternalUserJoined struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	DuplicateReport   *Report       `json:"duplicate_report,omitempty"`
	// DEPRECATED: Deprecated in favor of .duplicate_report
	DuplicateReportID *int32 `json:"duplicate_report_id,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ExternalUserRemoved activity for a report
type ActivitiesExternalUserRemoved struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	RemovedUser       *User     `json:"removed_user,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::GroupAssignedToBug activity for a report
type ActivitiesGroupAssignedToBug struct {
	ID_               *string          `json:"_id,omitempty"`
	Actor             *ActorUnion      `json:"actor,omitempty"`
	AssignedGroup     *TeamMemberGroup `json:"assigned_group,omitempty"`
	Attachments       []*Attachment    `json:"attachments,omitempty"`
	AutomatedResponse *bool            `json:"automated_response,omitempty"`
	CreatedAt         *DateTime        `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string `json:"genius_execution_id,omitempty"`
	// DEPRECATED: deprecated in favor of assigned group
	Group           *TeamMemberGroup `json:"group,omitempty"`
	ICanEdit        *bool            `json:"i_can_edit,omitempty"`
	ID              *string          `json:"id,omitempty"`
	Internal        *bool            `json:"internal,omitempty"`
	MarkdownMessage *string          `json:"markdown_message,omitempty"`
	Message         *string          `json:"message,omitempty"`
	Report          *Report          `json:"report,omitempty"`
	UpdatedAt       *DateTime        `json:"updated_at,omitempty"`
}

// A Activities::HackerRequestedMediation activity for a report
type ActivitiesHackerRequestedMediation struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ManuallyDisclosed activity for a report
type ActivitiesManuallyDisclosed struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::MediationRequested activity for a report
type ActivitiesMediationRequested struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::NotEligibleForBounty activity for a report
type ActivitiesNotEligibleForBounty struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReferenceIdAdded activity for a report
type ActivitiesReferenceIDAdded struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Reference         *string   `json:"reference,omitempty"`
	ReferenceURL      *string   `json:"reference_url,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::CveIdAdded activity for a report
type ActivitiesCVEIDAdded struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	CVEIds            []*string     `json:"cve_ids,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReassignedToTeam activity for a report
type ActivitiesReassignedToTeam struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportBecamePublic activity for a report
type ActivitiesReportBecamePublic struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportTitleUpdated activity for a report
type ActivitiesReportTitleUpdated struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	NewTitle          *string   `json:"new_title,omitempty"`
	OldTitle          *string   `json:"old_title,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportVulnerabilityTypesUpdated activity for a report
type ActivitiesReportVulnerabilityTypesUpdated struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	NewWeakness       *Weakness `json:"new_weakness,omitempty"`
	OldWeakness       *Weakness `json:"old_weakness,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportSeverityUpdated activity for a report
type ActivitiesReportSeverityUpdated struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportCollaboratorInvited activity for a report
type ActivitiesReportCollaboratorInvited struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ReportCollaboratorJoined activity for a report
type ActivitiesReportCollaboratorJoined struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::SwagAwarded activity for a report
type ActivitiesSwagAwarded struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	Swag              *Swag     `json:"swag,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::TeamPublished activity for a team
type ActivitiesTeamPublished struct {
	ID_             *string     `json:"_id,omitempty"`
	Actor           *ActorUnion `json:"actor,omitempty"`
	CreatedAt       *DateTime   `json:"created_at,omitempty"`
	ICanEdit        *bool       `json:"i_can_edit,omitempty"`
	ID              *string     `json:"id,omitempty"`
	Internal        *bool       `json:"internal,omitempty"`
	MarkdownMessage *string     `json:"markdown_message,omitempty"`
	Message         *string     `json:"message,omitempty"`
	UpdatedAt       *DateTime   `json:"updated_at,omitempty"`
}

// A Activities::UserAssignedToBug activity for a report
type ActivitiesUserAssignedToBug struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	AssignedUser      *User         `json:"assigned_user,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::UserBannedFromProgram activity for a report
type ActivitiesUserBannedFromProgram struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	RemovedUser       *User     `json:"removed_user,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::UserJoined activity for a user
type ActivitiesUserJoined struct {
	ID_             *string     `json:"_id,omitempty"`
	Actor           *ActorUnion `json:"actor,omitempty"`
	CreatedAt       *DateTime   `json:"created_at,omitempty"`
	ICanEdit        *bool       `json:"i_can_edit,omitempty"`
	ID              *string     `json:"id,omitempty"`
	Internal        *bool       `json:"internal,omitempty"`
	MarkdownMessage *string     `json:"markdown_message,omitempty"`
	Message         *string     `json:"message,omitempty"`
	UpdatedAt       *DateTime   `json:"updated_at,omitempty"`
}

// An Activities::NobodyAssignedToBug activity for a report
type ActivitiesNobodyAssignedToBug struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::ProgramInactive activity for a report
type ActivitiesProgramInactive struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// A Activities::UserCompletedRetest activity for a report
type ActivitiesUserCompletedRetest struct {
	ID_               *string       `json:"_id,omitempty"`
	Actor             *ActorUnion   `json:"actor,omitempty"`
	Attachments       []*Attachment `json:"attachments,omitempty"`
	AutomatedResponse *bool         `json:"automated_response,omitempty"`
	CreatedAt         *DateTime     `json:"created_at,omitempty"`
	// DEPRECATED: This is about to be replaced by .genius_execution
	GeniusExecutionID *string   `json:"genius_execution_id,omitempty"`
	ICanEdit          *bool     `json:"i_can_edit,omitempty"`
	ID                *string   `json:"id,omitempty"`
	Internal          *bool     `json:"internal,omitempty"`
	MarkdownMessage   *string   `json:"markdown_message,omitempty"`
	Message           *string   `json:"message,omitempty"`
	Report            *Report   `json:"report,omitempty"`
	UpdatedAt         *DateTime `json:"updated_at,omitempty"`
}

// The connection type for SlackPipeline.
type SlackPipelineConnection struct {
	// A list of edges.
	Edges []*SlackPipelineEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*SlackPipeline `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type SlackPipelineEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *SlackPipeline `json:"node,omitempty"`
}

// A Slack Pipeline Configuration for notifications
type SlackPipeline struct {
	// The primary key from the database
	ID_                                    *string   `json:"_id,omitempty"`
	Channel                                *string   `json:"channel,omitempty"`
	DescriptiveLabel                       *string   `json:"descriptive_label,omitempty"`
	ID                                     *string   `json:"id,omitempty"`
	NotificationReportAgreedOnGoingPublic  *bool     `json:"notification_report_agreed_on_going_public,omitempty"`
	NotificationReportAssigneeChanged      *bool     `json:"notification_report_assignee_changed,omitempty"`
	NotificationReportBecamePublic         *bool     `json:"notification_report_became_public,omitempty"`
	NotificationReportBountyPaid           *bool     `json:"notification_report_bounty_paid,omitempty"`
	NotificationReportBountySuggested      *bool     `json:"notification_report_bounty_suggested,omitempty"`
	NotificationReportBugClosedAsSpam      *bool     `json:"notification_report_bug_closed_as_spam,omitempty"`
	NotificationReportBugDuplicate         *bool     `json:"notification_report_bug_duplicate,omitempty"`
	NotificationReportBugInformative       *bool     `json:"notification_report_bug_informative,omitempty"`
	NotificationReportBugNeedsMoreInfo     *bool     `json:"notification_report_bug_needs_more_info,omitempty"`
	NotificationReportBugNew               *bool     `json:"notification_report_bug_new,omitempty"`
	NotificationReportBugNotApplicable     *bool     `json:"notification_report_bug_not_applicable,omitempty"`
	NotificationReportClosedAsResolved     *bool     `json:"notification_report_closed_as_resolved,omitempty"`
	NotificationReportCommentsClosed       *bool     `json:"notification_report_comments_closed,omitempty"`
	NotificationReportCreated              *bool     `json:"notification_report_created,omitempty"`
	NotificationReportInternalCommentAdded *bool     `json:"notification_report_internal_comment_added,omitempty"`
	NotificationReportManuallyDisclosed    *bool     `json:"notification_report_manually_disclosed,omitempty"`
	NotificationReportNotEligibleForBounty *bool     `json:"notification_report_not_eligible_for_bounty,omitempty"`
	NotificationReportPublicCommentAdded   *bool     `json:"notification_report_public_comment_added,omitempty"`
	NotificationReportReopened             *bool     `json:"notification_report_reopened,omitempty"`
	NotificationReportSwagAwarded          *bool     `json:"notification_report_swag_awarded,omitempty"`
	NotificationReportTriaged              *bool     `json:"notification_report_triaged,omitempty"`
	Team                                   *Team     `json:"team,omitempty"`
	UpdatedAt                              *DateTime `json:"updated_at,omitempty"`
	URL                                    *URI      `json:"url,omitempty"`
}

// The connection type for TeamMember.
type TeamMemberConnection struct {
	// A list of edges.
	Edges []*TeamMemberEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*TeamMember `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TeamMemberEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *TeamMember `json:"node,omitempty"`
}

type TeamMemberOrder struct {
	Direction *OrderDirection       `json:"direction,omitempty"`
	Field     *TeamMemberOrderField `json:"field,omitempty"`
}

// Fields on which a collection of team members can be ordered
type TeamMemberOrderField string

const (
	TeamMemberOrderFieldUsername TeamMemberOrderField = "username"
)

// SLA types
type SLATypeEnum string

const (
	SLATypeEnumFirstProgramResponse SLATypeEnum = "first_program_response"
	SLATypeEnumReportTriage         SLATypeEnum = "report_triage"
)

// The connection type for Swag.
type SwagConnection struct {
	// Boolean
	Any *bool `json:"any,omitempty"`
	// A list of edges.
	Edges []*SwagEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Swag `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// An edge in a connection.
type SwagEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Swag `json:"node,omitempty"`
}

// The connection type for ProfileMetricsSnapshot.
type ProfileMetricsSnapshotConnection struct {
	// A list of edges.
	Edges []*ProfileMetricsSnapshotEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ProfileMetricsSnapshot `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ProfileMetricsSnapshotEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ProfileMetricsSnapshot `json:"node,omitempty"`
}

// Profile Metrics snapshot of a Team
type ProfileMetricsSnapshot struct {
	BountiesCount *float64 `json:"bounties_count,omitempty"`
	BountiesPaid  *float64 `json:"bounties_paid,omitempty"`
	ID            *string  `json:"id,omitempty"`
	Month         *int32   `json:"month,omitempty"`
	Year          *int32   `json:"year,omitempty"`
}

// The connection type for TeamInboxView.
type TeamInboxViewConnection struct {
	// A list of edges.
	Edges []*TeamInboxViewEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*TeamInboxView `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TeamInboxViewEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *TeamInboxView `json:"node,omitempty"`
}

// A team report filter preset
type TeamInboxView struct {
	ID_                *string             `json:"_id,omitempty"`
	AssignedToGroupIds []*int32            `json:"assigned_to_group_ids,omitempty"`
	AssignedToUserIds  []*int32            `json:"assigned_to_user_ids,omitempty"`
	BuiltIn            *bool               `json:"built_in,omitempty"`
	CreatedAt          *DateTime           `json:"created_at,omitempty"`
	Filters            []*ReportFilterEnum `json:"filters,omitempty"`
	Hackathons         []*int32            `json:"hackathons,omitempty"`
	ID                 *string             `json:"id,omitempty"`
	Key                *string             `json:"key,omitempty"`
	Name               *string             `json:"name,omitempty"`
	Position           *int32              `json:"position,omitempty"`
	ReporterIds        []*int32            `json:"reporter_ids,omitempty"`
	Severities         []*string           `json:"severities,omitempty"`
	Substates          []*ReportStateEnum  `json:"substates,omitempty"`
	Team               *Team               `json:"team,omitempty"`
	TextQuery          *string             `json:"text_query,omitempty"`
	UpdatedAt          *DateTime           `json:"updated_at,omitempty"`
	Visible            *bool               `json:"visible,omitempty"`
}

// Filters which can be used to query reports
type ReportFilterEnum string

const (
	ReportFilterEnumAssigned                  ReportFilterEnum = "assigned"
	ReportFilterEnumAssignedToMe              ReportFilterEnum = "assigned_to_me"
	ReportFilterEnumUnassigned                ReportFilterEnum = "unassigned"
	ReportFilterEnumNotPublic                 ReportFilterEnum = "not_public"
	ReportFilterEnumPublic                    ReportFilterEnum = "public"
	ReportFilterEnumGoingPublicUser           ReportFilterEnum = "going_public_user"
	ReportFilterEnumGoingPublicTeam           ReportFilterEnum = "going_public_team"
	ReportFilterEnumBountyAwarded             ReportFilterEnum = "bounty_awarded"
	ReportFilterEnumNoBountyAwarded           ReportFilterEnum = "no_bounty_awarded"
	ReportFilterEnumIneligibleForBounty       ReportFilterEnum = "ineligible_for_bounty"
	ReportFilterEnumSLAViolation              ReportFilterEnum = "sla_violation"
	ReportFilterEnumSwagAwarded               ReportFilterEnum = "swag_awarded"
	ReportFilterEnumNoSwagAwarded             ReportFilterEnum = "no_swag_awarded"
	ReportFilterEnumReporterIsActive          ReportFilterEnum = "reporter_is_active"
	ReportFilterEnumNeedsFirstProgramResponse ReportFilterEnum = "needs_first_program_response"
	ReportFilterEnumHackerRequestedMediation  ReportFilterEnum = "hacker_requested_mediation"
)

type TeamInboxViewOrder struct {
	Direction *OrderDirection          `json:"direction,omitempty"`
	Field     *TeamInboxViewOrderField `json:"field,omitempty"`
}

// Fields on which a collection of team inbox views can be ordered
type TeamInboxViewOrderField string

const (
	TeamInboxViewOrderFieldPosition TeamInboxViewOrderField = "position"
)

// The connection type for CommonResponse.
type CommonResponseConnection struct {
	// A list of edges.
	Edges []*CommonResponseEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*CommonResponse `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type CommonResponseEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *CommonResponse `json:"node,omitempty"`
}

// A common response
type CommonResponse struct {
	// The primary key from the database
	ID_       *string   `json:"_id,omitempty"`
	CreatedAt *DateTime `json:"created_at,omitempty"`
	ID        *string   `json:"id,omitempty"`
	Message   *string   `json:"message,omitempty"`
	Team      *Team     `json:"team,omitempty"`
	Title     *string   `json:"title,omitempty"`
	UpdatedAt *DateTime `json:"updated_at,omitempty"`
}

type CommonResponseOrder struct {
	Direction *OrderDirection           `json:"direction,omitempty"`
	Field     *CommonResponseOrderField `json:"field,omitempty"`
}

// Fields on which a collection of common responses can be ordered
type CommonResponseOrderField string

const (
	CommonResponseOrderFieldTitle CommonResponseOrderField = "title"
)

// The connection type for Weakness.
type DeprecatedTeamWeaknessConnection struct {
	// A list of edges.
	Edges []*DeprecatedTeamWeaknessEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Weakness `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type DeprecatedTeamWeaknessEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node         *Weakness     `json:"node,omitempty"`
	TeamWeakness *TeamWeakness `json:"team_weakness,omitempty"`
}

// The connection type for TeamWeakness.
type TeamWeaknessConnection struct {
	// A list of edges.
	Edges []*TeamWeaknessEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*TeamWeakness `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TeamWeaknessEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *TeamWeakness `json:"node,omitempty"`
}

// The connection type for StructuredScope.
type StructuredScopesConnection struct {
	// A list of edges.
	Edges        []*StructuredScopeEdge `json:"edges,omitempty"`
	MaxUpdatedAt *DateTime              `json:"max_updated_at,omitempty"`
	// A list of nodes.
	Nodes []*StructuredScope `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type StructuredScopeEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *StructuredScope `json:"node,omitempty"`
}

// The connection type for InvitationUnion.
type InvitationUnionConnection struct {
	// A list of edges.
	Edges []*InvitationUnionEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*InvitationUnion `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type InvitationUnionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *InvitationUnion `json:"node,omitempty"`
}

// Invitations can be of multiple types
type InvitationUnion struct {
	TypeName__            string                 `json:"__typename,omitempty"`
	InvitationsSoftLaunch *InvitationsSoftLaunch `json:"-"`
}

func (u *InvitationUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType InvitationUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "InvitationsSoftLaunch":
		u.InvitationsSoftLaunch = &InvitationsSoftLaunch{}
		payload = u.InvitationsSoftLaunch
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// An invitation to join a private team as a hacker
type InvitationsSoftLaunch struct {
	ID_             *string               `json:"_id,omitempty"`
	ExpiresAt       *DateTime             `json:"expires_at,omitempty"`
	ID              *string               `json:"id,omitempty"`
	MarkdownMessage *string               `json:"markdown_message,omitempty"`
	Message         *string               `json:"message,omitempty"`
	Source          *InvitationSourceEnum `json:"source,omitempty"`
	State           *InvitationStateEnum  `json:"state,omitempty"`
	Team            *Team                 `json:"team,omitempty"`
	Token           *string               `json:"token,omitempty"`
}

// An interface for the common fields on a HackerOne Invitation
type InvitationInterface struct {
	ID_                   *string                `json:"_id,omitempty"`
	TypeName__            string                 `json:"__typename,omitempty"`
	InvitationsRetest     *InvitationsRetest     `json:"-"`
	InvitationsSoftLaunch *InvitationsSoftLaunch `json:"-"`
}

func (u *InvitationInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType InvitationInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "InvitationsRetest":
		u.InvitationsRetest = &InvitationsRetest{}
		payload = u.InvitationsRetest
	case "InvitationsSoftLaunch":
		u.InvitationsSoftLaunch = &InvitationsSoftLaunch{}
		payload = u.InvitationsSoftLaunch
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// Invitation source types
type InvitationSourceEnum string

const (
	InvitationSourceEnumUnknownInvite               InvitationSourceEnum = "unknown_invite"
	InvitationSourceEnumSystemInvite                InvitationSourceEnum = "system_invite"
	InvitationSourceEnumManualInvite                InvitationSourceEnum = "manual_invite"
	InvitationSourceEnumManualSkillsetInvitation    InvitationSourceEnum = "manual_skillset_invitation"
	InvitationSourceEnumAutomaticInvite             InvitationSourceEnum = "automatic_invite"
	InvitationSourceEnumPreviewHackerMatchingInvite InvitationSourceEnum = "preview_hacker_matching_invite"
	InvitationSourceEnumPriorityQueueInvite         InvitationSourceEnum = "priority_queue_invite"
	InvitationSourceEnumReportDraftInvite           InvitationSourceEnum = "report_draft_invite"
	InvitationSourceEnumSamlProvisioningInvite      InvitationSourceEnum = "saml_provisioning_invite"
	InvitationSourceEnumFacebookInvite              InvitationSourceEnum = "facebook_invite"
	InvitationSourceEnumStrictMfaReinvite           InvitationSourceEnum = "strict_mfa_reinvite"
	InvitationSourceEnumRecommendedProgramEnroll    InvitationSourceEnum = "recommended_program_enroll"
	InvitationSourceEnumH14420Invite                InvitationSourceEnum = "h14420_invite"
)

// States an invitation can be in
type InvitationStateEnum string

const (
	InvitationStateEnumAccepted            InvitationStateEnum = "accepted"
	InvitationStateEnumCancelled           InvitationStateEnum = "cancelled"
	InvitationStateEnumRejected            InvitationStateEnum = "rejected"
	InvitationStateEnumExpired             InvitationStateEnum = "expired"
	InvitationStateEnumPendingRequirements InvitationStateEnum = "pending_requirements"
	InvitationStateEnumOpen                InvitationStateEnum = "open"
)

// The connection type for SurveyAnswer.
type SurveyAnswerConnection struct {
	// A list of edges.
	Edges []*SurveyAnswerEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*SurveyAnswer `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo               `json:"pageInfo,omitempty"`
	Statistics *SurveyAnswerStatistics `json:"statistics,omitempty"`
	TotalCount *int32                  `json:"total_count,omitempty"`
}

// An edge in a connection.
type SurveyAnswerEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *SurveyAnswer `json:"node,omitempty"`
}

// A survey filled out by a hacker
type SurveyAnswer struct {
	ID_                       *string                             `json:"_id,omitempty"`
	CreatedAt                 *DateTime                           `json:"created_at,omitempty"`
	Feedback                  *string                             `json:"feedback,omitempty"`
	ID                        *string                             `json:"id,omitempty"`
	SourceType                *string                             `json:"source_type,omitempty"`
	SurveyStructuredResponses *SurveyStructuredResponseConnection `json:"survey_structured_responses,omitempty"`
	Team                      *Team                               `json:"team,omitempty"`
	UpdatedAt                 *DateTime                           `json:"updated_at,omitempty"`
	User                      *User                               `json:"user,omitempty"`
}

// The connection type for SurveyStructuredResponse.
type SurveyStructuredResponseConnection struct {
	// A list of edges.
	Edges []*SurveyStructuredResponseEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*SurveyStructuredResponse `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type SurveyStructuredResponseEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *SurveyStructuredResponse `json:"node,omitempty"`
}

// Prepared survey response reasons
type SurveyStructuredResponse struct {
	ID_        *string `json:"_id,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
	HelperText *string `json:"helper_text,omitempty"`
	ID         *string `json:"id,omitempty"`
	Reason     *string `json:"reason,omitempty"`
	Survey     *Survey `json:"survey,omitempty"`
}

// A HackerOne survey
type Survey struct {
	Category            *string                             `json:"category,omitempty"`
	ID                  *string                             `json:"id,omitempty"`
	Question            *string                             `json:"question,omitempty"`
	StructuredResponses *SurveyStructuredResponseConnection `json:"structured_responses,omitempty"`
	URL                 *URI                                `json:"url,omitempty"`
}

// Statistics for a reason hackers have selected in a survey
type SurveyAnswerStatistics struct {
	SurveyStructuredResponse *SurveyStructuredResponse `json:"survey_structured_response,omitempty"`
	TotalCount               *int32                    `json:"total_count,omitempty"`
}

// Survey Structured Response types
type SurveyStructuredResponseTypeEnum string

const (
	SurveyStructuredResponseTypeEnumUnresponsive     SurveyStructuredResponseTypeEnum = "unresponsive"
	SurveyStructuredResponseTypeEnumAggressivePolicy SurveyStructuredResponseTypeEnum = "aggressive_policy"
	SurveyStructuredResponseTypeEnumOnerousSetup     SurveyStructuredResponseTypeEnum = "onerous_setup"
	SurveyStructuredResponseTypeEnumSpecialization   SurveyStructuredResponseTypeEnum = "specialization"
	SurveyStructuredResponseTypeEnumHardened         SurveyStructuredResponseTypeEnum = "hardened"
	SurveyStructuredResponseTypeEnumSmallScope       SurveyStructuredResponseTypeEnum = "small_scope"
	SurveyStructuredResponseTypeEnumUninteresting    SurveyStructuredResponseTypeEnum = "uninteresting"
	SurveyStructuredResponseTypeEnumCompetitiveness  SurveyStructuredResponseTypeEnum = "competitiveness"
	SurveyStructuredResponseTypeEnumClarity          SurveyStructuredResponseTypeEnum = "clarity"
	SurveyStructuredResponseTypeEnumBacklog          SurveyStructuredResponseTypeEnum = "backlog"
	SurveyStructuredResponseTypeEnumBusy             SurveyStructuredResponseTypeEnum = "busy"
	SurveyStructuredResponseTypeEnumObjection        SurveyStructuredResponseTypeEnum = "objection"
)

type SurveyAnswerOrderInput struct {
	Direction *OrderDirection         `json:"direction,omitempty"`
	Field     *SurveyAnswerOrderField `json:"field,omitempty"`
}

// Fields on which a collection of survey answers can be ordered
type SurveyAnswerOrderField string

const (
	SurveyAnswerOrderFieldID SurveyAnswerOrderField = "id"
)

// An External Program
type ExternalProgram struct {
	// The primary key from the database
	ID_            *string `json:"_id,omitempty"`
	About          *string `json:"about,omitempty"`
	Handle         *string `json:"handle,omitempty"`
	ID             *string `json:"id,omitempty"`
	Name           *string `json:"name,omitempty"`
	ProfilePicture *string `json:"profile_picture,omitempty"`
	Team           *Team   `json:"team,omitempty"`
}

// The connection type for User.
type ParticipantConnection struct {
	// A list of edges.
	Edges []*ParticipantWithReputationEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*User `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
	YearRange  []*int32  `json:"year_range,omitempty"`
}

// An edge in a connection.
type ParticipantWithReputationEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *User `json:"node,omitempty"`
	// The participant's rank within the team
	Rank *int32 `json:"rank,omitempty"`
	// The participant's reputation within the team
	Reputation *int32 `json:"reputation,omitempty"`
}

type UserOrderInput struct {
	Direction *OrderDirection `json:"direction,omitempty"`
	Field     *UserOrderField `json:"field,omitempty"`
}

// Fields on which a collection of users can be ordered
type UserOrderField string

const (
	UserOrderFieldUsername   UserOrderField = "username"
	UserOrderFieldReputation UserOrderField = "reputation"
)

// The connection type for StaticParticipant.
type StaticParticipantConnection struct {
	// A list of edges.
	Edges []*StaticParticipantEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*StaticParticipant `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type StaticParticipantEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *StaticParticipant `json:"node,omitempty"`
}

// A static participant for a team
type StaticParticipant struct {
	ID_         *string `json:"_id,omitempty"`
	Avatar      *string `json:"avatar,omitempty"`
	Bio         *string `json:"bio,omitempty"`
	ExternalURL *string `json:"external_url,omitempty"`
	ID          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
	Year        *string `json:"year,omitempty"`
}

// The connection type for Post.
type TeamPostConnection struct {
	// A list of edges.
	Edges []*PostEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Post `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type PostEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Post `json:"node,omitempty"`
}

type Post struct {
	CreatedAt       *DateTime `json:"created_at,omitempty"`
	ID              *string   `json:"id,omitempty"`
	MarkdownMessage *string   `json:"markdown_message,omitempty"`
	Title           *string   `json:"title,omitempty"`
}

type TeamPostOrderInput struct {
	Direction *OrderDirection     `json:"direction,omitempty"`
	Field     *TeamPostOrderField `json:"field,omitempty"`
}

// Fields on which a collection of team posts can be ordered
type TeamPostOrderField string

const (
	TeamPostOrderFieldCreatedAt TeamPostOrderField = "created_at"
)

// Possible response efficiency indicators
type ResponseEfficiencyIndicatorEnum string

const (
	ResponseEfficiencyIndicatorEnumOk     ResponseEfficiencyIndicatorEnum = "ok"
	ResponseEfficiencyIndicatorEnumFailed ResponseEfficiencyIndicatorEnum = "failed"
	ResponseEfficiencyIndicatorEnumMissed ResponseEfficiencyIndicatorEnum = "missed"
)

// Display options for a HackerOne team
type TeamDisplayOptions struct {
	ID_                             *string `json:"_id,omitempty"`
	ID                              *string `json:"id,omitempty"`
	ShowAverageBounty               *bool   `json:"show_average_bounty,omitempty"`
	ShowMeanBountyTime              *bool   `json:"show_mean_bounty_time,omitempty"`
	ShowMeanFirstResponseTime       *bool   `json:"show_mean_first_response_time,omitempty"`
	ShowMeanReportTriageTime        *bool   `json:"show_mean_report_triage_time,omitempty"`
	ShowMeanResolutionTime          *bool   `json:"show_mean_resolution_time,omitempty"`
	ShowMinimumBounty               *bool   `json:"show_minimum_bounty,omitempty"`
	ShowReportsResolved             *bool   `json:"show_reports_resolved,omitempty"`
	ShowResponseEfficiencyIndicator *bool   `json:"show_response_efficiency_indicator,omitempty"`
	ShowTopBounties                 *bool   `json:"show_top_bounties,omitempty"`
	ShowTotalBountiesPaid           *bool   `json:"show_total_bounties_paid,omitempty"`
	Team                            *Team   `json:"team,omitempty"`
}

// Resolution SLA settings for a HackerOne team
type SLASetting struct {
	ID_                                        *string `json:"_id,omitempty"`
	CriticalSeverityResolvedStalenessThreshold *int32  `json:"critical_severity_resolved_staleness_threshold,omitempty"`
	HighSeverityResolvedStalenessThreshold     *int32  `json:"high_severity_resolved_staleness_threshold,omitempty"`
	ID                                         *string `json:"id,omitempty"`
	LowSeverityResolvedStalenessThreshold      *int32  `json:"low_severity_resolved_staleness_threshold,omitempty"`
	MediumSeverityResolvedStalenessThreshold   *int32  `json:"medium_severity_resolved_staleness_threshold,omitempty"`
	NoneSeverityResolvedStalenessThreshold     *int32  `json:"none_severity_resolved_staleness_threshold,omitempty"`
	UseAdvancedSettings                        *bool   `json:"use_advanced_settings,omitempty"`
}

// A HackerOne programs's submission requirements
type SubmissionRequirements struct {
	ID              *string `json:"id,omitempty"`
	MfaRequiredAt   *string `json:"mfa_required_at,omitempty"`
	TermsRequiredAt *string `json:"terms_required_at,omitempty"`
}

// BountyTable
type BountyTable struct {
	ID_             *string                   `json:"_id,omitempty"`
	BountyTableRows *BountyTableRowConnection `json:"bounty_table_rows,omitempty"`
	CriticalLabel   *string                   `json:"critical_label,omitempty"`
	Description     *string                   `json:"description,omitempty"`
	DescriptionHtml *string                   `json:"description_html,omitempty"`
	HighLabel       *string                   `json:"high_label,omitempty"`
	ID              *string                   `json:"id,omitempty"`
	LowLabel        *string                   `json:"low_label,omitempty"`
	MediumLabel     *string                   `json:"medium_label,omitempty"`
	Team            *Team                     `json:"team,omitempty"`
	URL             *URI                      `json:"url,omitempty"`
}

// The connection type for BountyTableRow.
type BountyTableRowConnection struct {
	// A list of edges.
	Edges []*BountyTableRowEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*BountyTableRow `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type BountyTableRowEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *BountyTableRow `json:"node,omitempty"`
}

// BountyTableRow
type BountyTableRow struct {
	ID_             *string          `json:"_id,omitempty"`
	Critical        *int32           `json:"critical,omitempty"`
	High            *int32           `json:"high,omitempty"`
	ID              *string          `json:"id,omitempty"`
	Low             *int32           `json:"low,omitempty"`
	Medium          *int32           `json:"medium,omitempty"`
	StructuredScope *StructuredScope `json:"structured_scope,omitempty"`
	URL             *URI             `json:"url,omitempty"`
}

// The connection type for Trigger.
type TriggerConnection struct {
	// A list of edges.
	Edges []*TriggerEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Trigger `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type TriggerEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Trigger `json:"node,omitempty"`
}

type TriggersOrder struct {
	Direction *OrderDirection    `json:"direction,omitempty"`
	Field     *TriggerOrderField `json:"field,omitempty"`
}

// Fields on which a collection of triggers can be ordered
type TriggerOrderField string

const (
	TriggerOrderFieldCreatedAt TriggerOrderField = "created_at"
)

// The connection type for CveRequest.
type CVERequestsConnection struct {
	// A list of edges.
	Edges []*CVERequestEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*CVERequest `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type CVERequestEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *CVERequest `json:"node,omitempty"`
}

// A request for a CVE
type CVERequest struct {
	ID_                       *string              `json:"_id,omitempty"`
	CreatedAt                 *DateTime            `json:"created_at,omitempty"`
	CVEIdentifier             *string              `json:"cve_identifier,omitempty"`
	Description               *string              `json:"description,omitempty"`
	ID                        *string              `json:"id,omitempty"`
	LatestStateChangeReason   *string              `json:"latest_state_change_reason,omitempty"`
	Owner                     *User                `json:"owner,omitempty"`
	Product                   *string              `json:"product,omitempty"`
	ProductVersion            *string              `json:"product_version,omitempty"`
	References                []*string            `json:"references,omitempty"`
	Report                    *Report              `json:"report,omitempty"`
	RequestType               *string              `json:"request_type,omitempty"`
	State                     *CVERequestStateEnum `json:"state,omitempty"`
	Team                      *Team                `json:"team,omitempty"`
	UpdatedAt                 *DateTime            `json:"updated_at,omitempty"`
	URL                       *URI                 `json:"url,omitempty"`
	VulnerabilityDiscoveredAt *DateTime            `json:"vulnerability_discovered_at,omitempty"`
	Weakness                  *Weakness            `json:"weakness,omitempty"`
}

// States of a CVE Request
type CVERequestStateEnum string

const (
	CVERequestStateEnumDraft                    CVERequestStateEnum = "draft"
	CVERequestStateEnumPendingHackeroneApproval CVERequestStateEnum = "pending_hackerone_approval"
	CVERequestStateEnumHackeroneApproved        CVERequestStateEnum = "hackerone_approved"
	CVERequestStateEnumPendingMitreApproval     CVERequestStateEnum = "pending_mitre_approval"
	CVERequestStateEnumMitreApproved            CVERequestStateEnum = "mitre_approved"
	CVERequestStateEnumCancelled                CVERequestStateEnum = "cancelled"
)

// Types of authentication methods for users
type AuthenticationServiceEnum string

const (
	AuthenticationServiceEnumSaml     AuthenticationServiceEnum = "saml"
	AuthenticationServiceEnumDatabase AuthenticationServiceEnum = "database"
	AuthenticationServiceEnumToken    AuthenticationServiceEnum = "token"
)

// A feature notification for all users
type NewFeatureNotification struct {
	Description *string `json:"description,omitempty"`
	ID          *string `json:"id,omitempty"`
	Key         *string `json:"key,omitempty"`
	Name        *string `json:"name,omitempty"`
	URL         *string `json:"url,omitempty"`
}

// A HackerOne feature
type Feature struct {
	ID_     *string `json:"_id,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	ID      *string `json:"id,omitempty"`
	Key     *string `json:"key,omitempty"`
}

// Invitation settings for users
type HackerInvitationsProfile struct {
	BountyProgramsOnly  *bool    `json:"bounty_programs_only,omitempty"`
	ID                  *string  `json:"id,omitempty"`
	ManagedProgramsOnly *bool    `json:"managed_programs_only,omitempty"`
	MinBounty           *float64 `json:"min_bounty,omitempty"`
	ReceiveInvites      *bool    `json:"receive_invites,omitempty"`
}

// The connection type for Bounty.
type BountyConnection struct {
	AverageAmount *float64 `json:"average_amount,omitempty"`
	// A list of edges.
	Edges []*BountyEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Bounty `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo           *PageInfo `json:"pageInfo,omitempty"`
	TotalAmount        *float64  `json:"total_amount,omitempty"`
	TotalAwardedAmount *float64  `json:"total_awarded_amount,omitempty"`
	TotalCount         *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type BountyEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Bounty `json:"node,omitempty"`
}

type FiltersBountyFilterInput struct {
	Or_       []*FiltersBountyFilterInput `json:"_or,omitempty"`
	And_      []*FiltersBountyFilterInput `json:"_and,omitempty"`
	ID        *IntPredicateInput          `json:"id,omitempty"`
	CreatedAt *DateTimePredicateInput     `json:"created_at,omitempty"`
}

// Possible currencies codes for bounties
type CurrencyCode string

const (
	CurrencyCodeXLA CurrencyCode = "XLA"
	CurrencyCodeUSD CurrencyCode = "USD"
)

// The connection type for Team.
type WhitelistedTeamConnection struct {
	// A list of edges.
	Edges []*WhitelistedTeamInformationEdgeType `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Team `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type WhitelistedTeamInformationEdgeType struct {
	// The participant's total bounty earned within the team
	BountyEarned *float64 `json:"bounty_earned,omitempty"`
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The participant's date of accepted the teams invitation
	LastInvitationAcceptedAt *DateTime `json:"last_invitation_accepted_at,omitempty"`
	// The item at the end of the edge.
	Node *Team `json:"node,omitempty"`
	// The participant's number of reports within the team
	NumberOfReports *int32 `json:"number_of_reports,omitempty"`
	// The participant's number of valid reports within the team
	NumberOfValidReports *int32 `json:"number_of_valid_reports,omitempty"`
}

type MembershipOrderInput struct {
	Field     *MembershipOrderField `json:"field,omitempty"`
	Direction *OrderDirection       `json:"direction,omitempty"`
}

// Fields on which a collection of Memberships can be ordered
type MembershipOrderField string

const (
	MembershipOrderFieldTEAMNAME MembershipOrderField = "TEAM_NAME"
)

// The connection type for BadgesUsers.
type BadgesUsersConnection struct {
	// A list of edges.
	Edges []*BadgesUsersEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*BadgesUsers `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type BadgesUsersEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *BadgesUsers `json:"node,omitempty"`
}

// Represents a badge earned by a user
type BadgesUsers struct {
	ID_       *string   `json:"_id,omitempty"`
	Badge     *Badge    `json:"badge,omitempty"`
	CreatedAt *DateTime `json:"created_at,omitempty"`
	ID        *string   `json:"id,omitempty"`
	User      *User     `json:"user,omitempty"`
}

// A HackerOne badge
type Badge struct {
	ID_         *string `json:"_id,omitempty"`
	Description *string `json:"description,omitempty"`
	ID          *string `json:"id,omitempty"`
	ImagePath   *string `json:"image_path,omitempty"`
	Name        *string `json:"name,omitempty"`
}

// The connection type for ProgramHealthAcknowledgement.
type ProgramHealthAcknowledgementConnection struct {
	// A list of edges.
	Edges []*ProgramHealthAcknowledgementEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ProgramHealthAcknowledgement `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ProgramHealthAcknowledgementEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ProgramHealthAcknowledgement `json:"node,omitempty"`
}

// A program_health_acknowledgement for a team_member
type ProgramHealthAcknowledgement struct {
	Acknowledged *bool                                   `json:"acknowledged,omitempty"`
	CreatedAt    *DateTime                               `json:"created_at,omitempty"`
	Dismissed    *bool                                   `json:"dismissed,omitempty"`
	ID           *string                                 `json:"id,omitempty"`
	Reason       *ProgramHealthAcknowledgementReasonEnum `json:"reason,omitempty"`
	TeamMember   *TeamMember                             `json:"team_member,omitempty"`
}

// reason which reflect the state of a program health acknowledgement
type ProgramHealthAcknowledgementReasonEnum string

const (
	ProgramHealthAcknowledgementReasonEnumGracePeriod ProgramHealthAcknowledgementReasonEnum = "grace_period"
	ProgramHealthAcknowledgementReasonEnumInReview    ProgramHealthAcknowledgementReasonEnum = "in_review"
	ProgramHealthAcknowledgementReasonEnumPaused      ProgramHealthAcknowledgementReasonEnum = "paused"
	ProgramHealthAcknowledgementReasonEnumOk          ProgramHealthAcknowledgementReasonEnum = "ok"
)

// The connection type for InvitationsSoftLaunch.
type SoftLaunchConnection struct {
	// A list of edges.
	Edges []*InvitationsSoftLaunchEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*InvitationsSoftLaunch `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type InvitationsSoftLaunchEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *InvitationsSoftLaunch `json:"node,omitempty"`
}

type InvitationOrderInput struct {
	Direction *OrderDirection       `json:"direction,omitempty"`
	Field     *InvitationOrderField `json:"field,omitempty"`
}

// Fields on which a collection of Invitation can be ordered
type InvitationOrderField string

const (
	InvitationOrderFieldInvitationExpiresAt InvitationOrderField = "invitation_expires_at"
)

// The connection type for InvitationQueue.
type InvitationQueueConnection struct {
	// A list of edges.
	Edges []*InvitationQueueEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*InvitationQueue `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type InvitationQueueEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *InvitationQueue `json:"node,omitempty"`
}

// A HackerOne invitation queue slot earned by a hacker
type InvitationQueue struct {
	ID_ *string `json:"_id,omitempty"`
	ID  *string `json:"id,omitempty"`
}

// The connection type for UserSession.
type UserSessionConnection struct {
	// A list of edges.
	Edges []*UserSessionEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*UserSession `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type UserSessionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *UserSession `json:"node,omitempty"`
}

// A HackerOne user's session history
type UserSession struct {
	ID_                  *string             `json:"_id,omitempty"`
	AbbreviatedUserAgent *string             `json:"abbreviated_user_agent,omitempty"`
	Country              *UserSessionCountry `json:"country,omitempty"`
	CreatedAt            *DateTime           `json:"created_at,omitempty"`
	Current              *bool               `json:"current,omitempty"`
	DeactivatedAt        *DateTime           `json:"deactivated_at,omitempty"`
	DeviceType           *string             `json:"device_type,omitempty"`
	ID                   *string             `json:"id,omitempty"`
	IpAddress            *string             `json:"ip_address,omitempty"`
	SessionLastUsedAt    *string             `json:"session_last_used_at,omitempty"`
	UserAgent            *string             `json:"user_agent,omitempty"`
}

// Country of a HackerOne user's session
type UserSessionCountry struct {
	Abbreviation *string `json:"abbreviation,omitempty"`
	Flag         *string `json:"flag,omitempty"`
	ID           *string `json:"id,omitempty"`
	Name         *string `json:"name,omitempty"`
}

// The connection type for ReportRetestUser.
type ReportRetestUserConnection struct {
	CompletedCount *int32 `json:"completed_count,omitempty"`
	// A list of edges.
	Edges []*ReportRetestUserEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ReportRetestUser `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount         *int32 `json:"total_count,omitempty"`
	TotalPaymentAmount *int32 `json:"total_payment_amount,omitempty"`
}

// An edge in a connection.
type ReportRetestUserEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ReportRetestUser `json:"node,omitempty"`
}

// A report retest user
type ReportRetestUser struct {
	ID_                      *string            `json:"_id,omitempty"`
	AnsweredCanBeReproduced  *bool              `json:"answered_can_be_reproduced,omitempty"`
	AnsweredFixCanBeBypassed *bool              `json:"answered_fix_can_be_bypassed,omitempty"`
	BypassReportID           *int32             `json:"bypass_report_id,omitempty"`
	CompletedAt              *DateTime          `json:"completed_at,omitempty"`
	ID                       *string            `json:"id,omitempty"`
	Invitation               *InvitationsRetest `json:"invitation,omitempty"`
	ReportRetest             *ReportRetest      `json:"report_retest,omitempty"`
	Status                   *BountyStatusEnum  `json:"status,omitempty"`
	User                     *User              `json:"user,omitempty"`
}

// A report retest
type ReportRetest struct {
	ID_               *string                     `json:"_id,omitempty"`
	AwardAmount       *string                     `json:"award_amount,omitempty"`
	CreatedAt         *DateTime                   `json:"created_at,omitempty"`
	CreatedBy         *User                       `json:"created_by,omitempty"`
	ID                *string                     `json:"id,omitempty"`
	Report            *Report                     `json:"report,omitempty"`
	ReportRetestUsers *ReportRetestUserConnection `json:"report_retest_users,omitempty"`
}

// An invitation to perform a retest of a report
type InvitationsRetest struct {
	ID_        *string   `json:"_id,omitempty"`
	AcceptedAt *DateTime `json:"accepted_at,omitempty"`
	ExpiresAt  *DateTime `json:"expires_at,omitempty"`
	ID         *string   `json:"id,omitempty"`
	Report     *Report   `json:"report,omitempty"`
	Team       *Team     `json:"team,omitempty"`
	Token      *string   `json:"token,omitempty"`
}

// Global accessible information about the HackerOne application
type Application struct {
	ID         *string   `json:"id,omitempty"`
	SystemTime *DateTime `json:"system_time,omitempty"`
}

// Calculate CVSS Severity score and rating
type SeverityCalculator struct {
	CalculatedMaxSeverity *SeverityRatingEnum `json:"calculated_max_severity,omitempty"`
	ID                    *string             `json:"id,omitempty"`
}

// The connection type for ExternalProgram.
type ExternalProgramConnection struct {
	// A list of edges.
	Edges []*ExternalProgramEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*ExternalProgram `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type ExternalProgramEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *ExternalProgram `json:"node,omitempty"`
}

// The connection type for SlaStatus.
type SLAStatusConnection struct {
	// A list of edges.
	Edges []*SLAStatusEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*SLAStatus `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type SLAStatusEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *SLAStatus `json:"node,omitempty"`
}

type SLAStatusOrder struct {
	Field *SLAStatusOrderField `json:"field,omitempty"`
}

// Fields on which a collection of SLA statuses can be ordered
type SLAStatusOrderField string

const (
	SLAStatusOrderFieldTRIAGERROLEANDSLASTATUS SLAStatusOrderField = "TRIAGER_ROLE_AND_SLA_STATUS"
)

// Resources for setting up the Bank Transfer payment method
type BankTransferReference struct {
	BeneficiaryRequiredDetails *BeneficiaryRequiredDetail `json:"beneficiary_required_details,omitempty"`
	Countries                  []*Country                 `json:"countries,omitempty"`
	Currencies                 []*Currency                `json:"currencies,omitempty"`
	ID                         *string                    `json:"id,omitempty"`
}

// A currency as defined by ISO 4217
type Currency struct {
	Code *string `json:"code,omitempty"`
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// A country as specified in ISO 3166
type Country struct {
	Alpha2       *string `json:"alpha2,omitempty"`
	CurrencyCode *string `json:"currency_code,omitempty"`
	ID           *string `json:"id,omitempty"`
	Name         *string `json:"name,omitempty"`
}

// A specification of information needed to create a bank transfer payment preference
type BeneficiaryRequiredDetail struct {
	BankAccountCountry         *string                               `json:"bank_account_country,omitempty"`
	BeneficiaryCountry         *string                               `json:"beneficiary_country,omitempty"`
	BeneficiaryRequiredDetails *BeneficiaryRequiredDetailsConnection `json:"beneficiary_required_details,omitempty"`
	Currency                   *string                               `json:"currency,omitempty"`
	ID                         *string                               `json:"id,omitempty"`
}

// The connection type for BeneficiaryRequiredDetails.
type BeneficiaryRequiredDetailsConnection struct {
	// A list of edges.
	Edges []*BeneficiaryRequiredDetailsEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*BeneficiaryRequiredDetails `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type BeneficiaryRequiredDetailsEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *BeneficiaryRequiredDetails `json:"node,omitempty"`
}

// A specification of the possibilities for creating a bank transfer payout preference
type BeneficiaryRequiredDetails struct {
	BeneficiaryEntityType     *string                             `json:"beneficiary_entity_type,omitempty"`
	BeneficiaryRequiredFields *BeneficiaryRequiredFieldConnection `json:"beneficiary_required_fields,omitempty"`
	Description               *string                             `json:"description,omitempty"`
	Fee                       *string                             `json:"fee,omitempty"`
	ID                        *string                             `json:"id,omitempty"`
	PaymentType               *string                             `json:"payment_type,omitempty"`
}

// The connection type for BeneficiaryRequiredField.
type BeneficiaryRequiredFieldConnection struct {
	// A list of edges.
	Edges []*BeneficiaryRequiredFieldEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*BeneficiaryRequiredField `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
}

// An edge in a connection.
type BeneficiaryRequiredFieldEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *BeneficiaryRequiredField `json:"node,omitempty"`
}

// A specification of the format of a field used to create a bank transfer payout preference
type BeneficiaryRequiredField struct {
	Description *string `json:"description,omitempty"`
	Field       *string `json:"field,omitempty"`
	ID          *string `json:"id,omitempty"`
	Regex       *string `json:"regex,omitempty"`
}

// The connection type for Survey.
type SurveyConnection struct {
	// A list of edges.
	Edges []*SurveyEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Survey `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type SurveyEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Survey `json:"node,omitempty"`
}

// Survey categories
type SurveyCategoryEnum string

const (
	SurveyCategoryEnumInvitationRejection SurveyCategoryEnum = "invitation_rejection"
	SurveyCategoryEnumProgramLeave        SurveyCategoryEnum = "program_leave"
)

// An OAuth Application that can use a 'Sign in using HackerOne' flow and be given OAuth Access Tokens.
type OauthApplication struct {
	ClientID *string   `json:"client_id,omitempty"`
	Name     *string   `json:"name,omitempty"`
	Scopes   []*string `json:"scopes,omitempty"`
}

// The connection type for HacktivityItemUnion.
type HacktivityItemConnection struct {
	// A list of edges.
	Edges []*HacktivityItemUnionEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*HacktivityItemUnion `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type HacktivityItemUnionEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *HacktivityItemUnion `json:"node,omitempty"`
}

// Hacktivities can be of multiple types
type HacktivityItemUnion struct {
	TypeName__      string           `json:"__typename,omitempty"`
	Disclosed       *Disclosed       `json:"-"`
	Undisclosed     *Undisclosed     `json:"-"`
	HackerPublished *HackerPublished `json:"-"`
}

func (u *HacktivityItemUnion) UnmarshalJSON(data []byte) (err error) {
	type tmpType HacktivityItemUnion
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "Disclosed":
		u.Disclosed = &Disclosed{}
		payload = u.Disclosed
	case "Undisclosed":
		u.Undisclosed = &Undisclosed{}
		payload = u.Undisclosed
	case "HackerPublished":
		u.HackerPublished = &HackerPublished{}
		payload = u.HackerPublished
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HacktivityItems::Disclosed for a report
type Disclosed struct {
	ID_                         *string             `json:"_id,omitempty"`
	CreatedAt                   *DateTime           `json:"created_at,omitempty"`
	Currency                    *string             `json:"currency,omitempty"`
	ID                          *string             `json:"id,omitempty"`
	LatestDisclosableAction     *string             `json:"latest_disclosable_action,omitempty"`
	LatestDisclosableActivityAt *DateTime           `json:"latest_disclosable_activity_at,omitempty"`
	Report                      *Report             `json:"report,omitempty"`
	Reporter                    *User               `json:"reporter,omitempty"`
	SeverityRating              *SeverityRatingEnum `json:"severity_rating,omitempty"`
	Team                        *Team               `json:"team,omitempty"`
	TotalAwardedAmount          *float64            `json:"total_awarded_amount,omitempty"`
	UpvotedByCurrentUser        *bool               `json:"upvoted_by_current_user,omitempty"`
	Votes                       *VoteConnection     `json:"votes,omitempty"`
}

// A HackerOne hacktivity item interface
type HacktivityItemInterface struct {
	ID_                  *string          `json:"_id,omitempty"`
	CreatedAt            *DateTime        `json:"created_at,omitempty"`
	ID                   *string          `json:"id,omitempty"`
	UpvotedByCurrentUser *bool            `json:"upvoted_by_current_user,omitempty"`
	Votes                *VoteConnection  `json:"votes,omitempty"`
	TypeName__           string           `json:"__typename,omitempty"`
	Disclosed            *Disclosed       `json:"-"`
	HackerPublished      *HackerPublished `json:"-"`
	Undisclosed          *Undisclosed     `json:"-"`
}

func (u *HacktivityItemInterface) UnmarshalJSON(data []byte) (err error) {
	type tmpType HacktivityItemInterface
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "Disclosed":
		u.Disclosed = &Disclosed{}
		payload = u.Disclosed
	case "HackerPublished":
		u.HackerPublished = &HackerPublished{}
		payload = u.HackerPublished
	case "Undisclosed":
		u.Undisclosed = &Undisclosed{}
		payload = u.Undisclosed
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// A HacktivityItems::Undisclosed for a report
type Undisclosed struct {
	ID_                         *string         `json:"_id,omitempty"`
	CreatedAt                   *DateTime       `json:"created_at,omitempty"`
	Currency                    *string         `json:"currency,omitempty"`
	ID                          *string         `json:"id,omitempty"`
	LatestDisclosableAction     *string         `json:"latest_disclosable_action,omitempty"`
	LatestDisclosableActivityAt *DateTime       `json:"latest_disclosable_activity_at,omitempty"`
	Reporter                    *User           `json:"reporter,omitempty"`
	RequiresViewPrivilege       *bool           `json:"requires_view_privilege,omitempty"`
	Team                        *Team           `json:"team,omitempty"`
	TotalAwardedAmount          *float64        `json:"total_awarded_amount,omitempty"`
	UpvotedByCurrentUser        *bool           `json:"upvoted_by_current_user,omitempty"`
	Votes                       *VoteConnection `json:"votes,omitempty"`
}

// A HacktivityItems::HackerPublished for a report
type HackerPublished struct {
	ID_                         *string             `json:"_id,omitempty"`
	CreatedAt                   *DateTime           `json:"created_at,omitempty"`
	ID                          *string             `json:"id,omitempty"`
	LatestDisclosableActivityAt *DateTime           `json:"latest_disclosable_activity_at,omitempty"`
	Report                      *Report             `json:"report,omitempty"`
	Reporter                    *User               `json:"reporter,omitempty"`
	SeverityRating              *SeverityRatingEnum `json:"severity_rating,omitempty"`
	Team                        *Team               `json:"team,omitempty"`
	UpvotedByCurrentUser        *bool               `json:"upvoted_by_current_user,omitempty"`
	Votes                       *VoteConnection     `json:"votes,omitempty"`
}

type HacktivityItemOrderInput struct {
	Direction *OrderDirection           `json:"direction,omitempty"`
	Field     *HacktivityOrderFieldEnum `json:"field,omitempty"`
}

// Fields on which a collection of HacktivityItems can be ordered
type HacktivityOrderFieldEnum string

const (
	HacktivityOrderFieldEnumPopular HacktivityOrderFieldEnum = "popular"
)

type FiltersHacktivityItemFilterOrder struct {
	Field     *FiltersHacktivityItemFilterOrderField `json:"field,omitempty"`
	Direction *FilterOrderDirectionEnum              `json:"direction,omitempty"`
}

type FiltersHacktivityItemFilterOrderField string

const (
	FiltersHacktivityItemFilterOrderFieldID                          FiltersHacktivityItemFilterOrderField = "id"
	FiltersHacktivityItemFilterOrderFieldLatestDisclosableActivityAt FiltersHacktivityItemFilterOrderField = "latest_disclosable_activity_at"
)

type FiltersHacktivityItemFilterInput struct {
	Or_                []*FiltersHacktivityItemFilterInput `json:"_or,omitempty"`
	And_               []*FiltersHacktivityItemFilterInput `json:"_and,omitempty"`
	ID                 *IntPredicateInput                  `json:"id,omitempty"`
	TotalAwardedAmount *StringPredicateInput               `json:"total_awarded_amount,omitempty"`
	Team               *FiltersTeamFilterInput             `json:"team,omitempty"`
	Reporter           *FiltersUserFilterInput             `json:"reporter,omitempty"`
	Report             *FiltersReportFilterInput           `json:"report,omitempty"`
}

// The connection type for Task.
type TaskConnection struct {
	// A list of edges.
	Edges []*TaskEdge `json:"edges,omitempty"`
	// Information to aid in pagination.
	PageInfo *PageInfo `json:"pageInfo,omitempty"`
	// Int
	TotalCount *int32 `json:"total_count,omitempty"`
}

// An edge in a connection.
type TaskEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Task `json:"node,omitempty"`
}

// Task
type Task struct {
	ID_         *string      `json:"_id,omitempty"`
	Completed   *bool        `json:"completed,omitempty"`
	Description *string      `json:"description,omitempty"`
	ID          *string      `json:"id,omitempty"`
	Key         *TaskKeyEnum `json:"key,omitempty"`
	URL         *URI         `json:"url,omitempty"`
}

// All valid task keys
type TaskKeyEnum string

const (
	TaskKeyEnumBOOKMARKPROGRAMS TaskKeyEnum = "BOOKMARK_PROGRAMS"
	TaskKeyEnumUPVOTEHACKTIVITY TaskKeyEnum = "UPVOTE_HACKTIVITY"
	TaskKeyEnumPARTAKECTF       TaskKeyEnum = "PARTAKE_CTF"
	TaskKeyEnumVALIDREPORT      TaskKeyEnum = "VALID_REPORT"
)

type Mutation struct {
	AcceptInvitation                                 *AcceptInvitationPayload                                 `json:"acceptInvitation,omitempty"`
	AcknowledgeProgramHealthAcknowledgement          *AcknowledgeProgramHealthAcknowledgementPayload          `json:"acknowledgeProgramHealthAcknowledgement,omitempty"`
	ArchiveStructuredScope                           *ArchiveStructuredScopePayload                           `json:"archiveStructuredScope,omitempty"`
	CancelTwoFactorAuthenticationReset               *CancelTwoFactorAuthenticationResetPayload               `json:"cancelTwoFactorAuthenticationReset,omitempty"`
	ClaimCredential                                  *ClaimCredentialPayload                                  `json:"claimCredential,omitempty"`
	ClaimReport                                      *ClaimReportPayload                                      `json:"claimReport,omitempty"`
	CompleteReportRetestUser                         *CompleteReportRetestUserPayload                         `json:"completeReportRetestUser,omitempty"`
	CreateActivityComment                            *CreateActivityCommentPayload                            `json:"createActivityComment,omitempty"`
	CreateBounty                                     *CreateBountyPayload                                     `json:"createBounty,omitempty"`
	CreateBountySuggestion                           *CreateBountySuggestionPayload                           `json:"createBountySuggestion,omitempty"`
	CreateCoinbasePayoutPreference                   *CreateCoinbasePayoutPreferencePayload                   `json:"createCoinbasePayoutPreference,omitempty"`
	CreateCurrencycloudBankTransferPayoutPreference  *CreateCurrencycloudBankTransferPayoutPreferencePayload  `json:"createCurrencycloudBankTransferPayoutPreference,omitempty"`
	CreateCVERequest                                 *CreateCVERequestPayload                                 `json:"createCveRequest,omitempty"`
	CreateExternalReport                             *CreateExternalReportPayload                             `json:"createExternalReport,omitempty"`
	CreateIssueTrackerReferenceID                    *CreateIssueTrackerReferenceIDPayload                    `json:"createIssueTrackerReferenceId,omitempty"`
	CreateJiraOauthURL                               *CreateJiraOauthURLPayload                               `json:"createJiraOauthUrl,omitempty"`
	CreateJiraWebhookToken                           *CreateJiraWebhookTokenPayload                           `json:"createJiraWebhookToken,omitempty"`
	CreateLeaveProgramSurveyAnswer                   *CreateLeaveProgramSurveyAnswerPayload                   `json:"createLeaveProgramSurveyAnswer,omitempty"`
	CreateMailingAddress                             *CreateMailingAddressPayload                             `json:"createMailingAddress,omitempty"`
	CreateOrUpdateHackeroneToJiraEventsConfiguration *CreateOrUpdateHackeroneToJiraEventsConfigurationPayload `json:"createOrUpdateHackeroneToJiraEventsConfiguration,omitempty"`
	CreateOrUpdateJiraIntegration                    *CreateOrUpdateJiraIntegrationPayload                    `json:"createOrUpdateJiraIntegration,omitempty"`
	CreatePaypalPreference                           *CreatePaypalPreferencePayload                           `json:"createPaypalPreference,omitempty"`
	CreateProgramBounty                              *CreateProgramBountyPayload                              `json:"createProgramBounty,omitempty"`
	CreateRejectionSurveyAnswer                      *CreateRejectionSurveyAnswerPayload                      `json:"createRejectionSurveyAnswer,omitempty"`
	CreateReport                                     *CreateReportPayload                                     `json:"createReport,omitempty"`
	CreateReportSummary                              *CreateReportSummaryPayload                              `json:"createReportSummary,omitempty"`
	CreateSlackPipeline                              *CreateSlackPipelinePayload                              `json:"createSlackPipeline,omitempty"`
	CreateStructuredScope                            *CreateStructuredScopePayload                            `json:"createStructuredScope,omitempty"`
	CreateSwag                                       *CreateSwagPayload                                       `json:"createSwag,omitempty"`
	CreateTaxForm                                    *CreateTaxFormPayload                                    `json:"createTaxForm,omitempty"`
	CreateTrigger                                    *CreateTriggerPayload                                    `json:"createTrigger,omitempty"`
	CreateTwoFactorAuthenticationCredentials         *CreateTwoFactorAuthenticationCredentialsPayload         `json:"createTwoFactorAuthenticationCredentials,omitempty"`
	CreateUserBountiesReport                         *CreateUserBountiesReportPayload                         `json:"createUserBountiesReport,omitempty"`
	CreateUserLufthansaAccount                       *CreateUserLufthansaAccountPayload                       `json:"createUserLufthansaAccount,omitempty"`
	CreateUserTwoFactorReset                         *CreateUserTwoFactorResetPayload                         `json:"createUserTwoFactorReset,omitempty"`
	CreateVpnCredentials                             *CreateVpnCredentialsPayload                             `json:"createVpnCredentials,omitempty"`
	DeleteBiDirectionalJiraIntegration               *DeleteBiDirectionalJiraIntegrationPayload               `json:"deleteBiDirectionalJiraIntegration,omitempty"`
	DeleteJiraWebhook                                *DeleteJiraWebhookPayload                                `json:"deleteJiraWebhook,omitempty"`
	DeleteMailingAddress                             *DeleteMailingAddressPayload                             `json:"deleteMailingAddress,omitempty"`
	DeletePhabricatorIntegration                     *DeletePhabricatorIntegrationPayload                     `json:"deletePhabricatorIntegration,omitempty"`
	DeleteSlackPipeline                              *DeleteSlackPipelinePayload                              `json:"deleteSlackPipeline,omitempty"`
	DeleteTeamMember                                 *DeleteTeamMemberPayload                                 `json:"deleteTeamMember,omitempty"`
	DeleteTeamSlackIntegration                       *DeleteTeamSlackIntegrationPayload                       `json:"deleteTeamSlackIntegration,omitempty"`
	DeleteTrigger                                    *DeleteTriggerPayload                                    `json:"deleteTrigger,omitempty"`
	DeleteUserLufthansaAccount                       *DeleteUserLufthansaAccountPayload                       `json:"deleteUserLufthansaAccount,omitempty"`
	DeleteUserSession                                *DeleteUserSessionPayload                                `json:"deleteUserSession,omitempty"`
	DestroyTwoFactorAuthenticationCredentials        *DestroyTwoFactorAuthenticationCredentialsPayload        `json:"destroyTwoFactorAuthenticationCredentials,omitempty"`
	DestroyUpvote                                    *DestroyUpvotePayload                                    `json:"destroyUpvote,omitempty"`
	DismissProgramHealthAcknowledgement              *DismissProgramHealthAcknowledgementPayload              `json:"dismissProgramHealthAcknowledgement,omitempty"`
	EnableUser                                       *EnableUserPayload                                       `json:"enableUser,omitempty"`
	ExportLifetimeReports                            *ExportLifetimeReportsPayload                            `json:"exportLifetimeReports,omitempty"`
	ForgetFacebookCredentials                        *ForgetFacebookCredentialPayload                         `json:"forgetFacebookCredentials,omitempty"`
	GenerateTaxFormURL                               *GenerateTaxFormURLPayload                               `json:"generateTaxFormUrl,omitempty"`
	LaunchTeam                                       *LaunchTeamPayload                                       `json:"launchTeam,omitempty"`
	LaunchTeamPublicly                               *LaunchTeamPubliclyPayload                               `json:"launchTeamPublicly,omitempty"`
	LeavePrivateProgram                              *LeavePrivateProgramPayload                              `json:"leavePrivateProgram,omitempty"`
	LockReport                                       *LockReportPayload                                       `json:"lockReport,omitempty"`
	MarkReportAsNeedsMoreInfo                        *MarkReportAsNeedsMoreInfoPayload                        `json:"markReportAsNeedsMoreInfo,omitempty"`
	MarkReportAsNoise                                *MarkReportAsNoisePayload                                `json:"markReportAsNoise,omitempty"`
	MarkReportAsSignal                               *MarkReportAsSignalPayload                               `json:"markReportAsSignal,omitempty"`
	ProgramHealthAcknowledgementSeen                 *ProgramHealthAcknowledgementSeenPayload                 `json:"programHealthAcknowledgementSeen,omitempty"`
	PublishPolicy                                    *PublishPolicyPayload                                    `json:"publishPolicy,omitempty"`
	RegenerateCalendarToken                          *RegenerateCalendarTokenPayload                          `json:"regenerateCalendarToken,omitempty"`
	RejectInvitation                                 *RejectInvitationPayload                                 `json:"rejectInvitation,omitempty"`
	RemoveBountyTable                                *RemoveBountyTablePayload                                `json:"removeBountyTable,omitempty"`
	RevokeCredential                                 *RevokeCredentialPayload                                 `json:"revokeCredential,omitempty"`
	StartVpnInstance                                 *StartVpnInstancePayload                                 `json:"startVpnInstance,omitempty"`
	StopVpnInstance                                  *StopVpnInstancePayload                                  `json:"stopVpnInstance,omitempty"`
	UnclaimReport                                    *UnclaimReportPayload                                    `json:"unclaimReport,omitempty"`
	UnsubscribeMailingList                           *UnsubscribeMailingListPayload                           `json:"unsubscribeMailingList,omitempty"`
	UpdateAccountRecoveryPhoneNumber                 *UpdateAccountRecoveryPhoneNumberPayload                 `json:"updateAccountRecoveryPhoneNumber,omitempty"`
	UpdateAssigneeToGroup                            *UpdateAssigneeToGroupPayload                            `json:"updateAssigneeToGroup,omitempty"`
	UpdateAssigneeToNobody                           *UpdateAssigneeToNobodyPayload                           `json:"updateAssigneeToNobody,omitempty"`
	UpdateAssigneeToUser                             *UpdateAssigneeToUserPayload                             `json:"updateAssigneeToUser,omitempty"`
	UpdateAutomaticInvites                           *UpdateAutomaticInvitesPayload                           `json:"updateAutomaticInvites,omitempty"`
	UpdateBookmarkedTeam                             *UpdateBookmarkedTeamPayload                             `json:"updateBookmarkedTeam,omitempty"`
	UpdateBountyTable                                *UpdateBountyTablePayload                                `json:"updateBountyTable,omitempty"`
	UpdateChallengeSetting                           *UpdateChallengeSettingPayload                           `json:"updateChallengeSetting,omitempty"`
	UpdateCredentialAccountDetails                   *UpdateCredentialAccountDetailPayload                    `json:"updateCredentialAccountDetails,omitempty"`
	UpdateCredentialInstruction                      *UpdateCredentialInstructionPayload                      `json:"updateCredentialInstruction,omitempty"`
	UpdateCVERequest                                 *UpdateCVERequestPayload                                 `json:"updateCveRequest,omitempty"`
	UpdateEmbeddedSubmissionDomains                  *UpdateEmbeddedSubmissionDomainPayload                   `json:"updateEmbeddedSubmissionDomains,omitempty"`
	UpdateFacebookUserID                             *UpdateFacebookUserIDPayload                             `json:"updateFacebookUserId,omitempty"`
	UpdateInvitationPreferences                      *UpdateInvitationPreferencesPayload                      `json:"updateInvitationPreferences,omitempty"`
	UpdateJiraWebhook                                *UpdateJiraWebhookPayload                                `json:"updateJiraWebhook,omitempty"`
	UpdateLastViewedNewFeaturesAt                    *UpdateLastViewedNewFeaturesAtPayload                    `json:"updateLastViewedNewFeaturesAt,omitempty"`
	UpdateMe                                         *UpdateMePayload                                         `json:"updateMe,omitempty"`
	UpdatePhabricatorIntegration                     *UpdatePhabricatorIntegrationPayload                     `json:"updatePhabricatorIntegration,omitempty"`
	UpdateReportCloseComments                        *UpdateReportCloseCommentsPayload                        `json:"updateReportCloseComments,omitempty"`
	UpdateReportStateToDuplicate                     *UpdateReportStateToDuplicatePayload                     `json:"updateReportStateToDuplicate,omitempty"`
	UpdateReportStateToInformative                   *UpdateReportStateToInformativePayload                   `json:"updateReportStateToInformative,omitempty"`
	UpdateReportStateToNeedsMoreInfo                 *UpdateReportStateToNeedsMoreInfoPayload                 `json:"updateReportStateToNeedsMoreInfo,omitempty"`
	UpdateReportStateToNew                           *UpdateReportStateToNewPayload                           `json:"updateReportStateToNew,omitempty"`
	UpdateReportStateToNotApplicable                 *UpdateReportStateToNotApplicablePayload                 `json:"updateReportStateToNotApplicable,omitempty"`
	UpdateReportStateToResolved                      *UpdateReportStateToResolvedPayload                      `json:"updateReportStateToResolved,omitempty"`
	UpdateReportStateToSpam                          *UpdateReportStateToSpamPayload                          `json:"updateReportStateToSpam,omitempty"`
	UpdateReportStateToTriaged                       *UpdateReportStateToTriagedPayload                       `json:"updateReportStateToTriaged,omitempty"`
	UpdateReportStructuredScope                      *UpdateReportStructuredScopePayload                      `json:"updateReportStructuredScope,omitempty"`
	UpdateReportTitle                                *UpdateReportTitlePayload                                `json:"updateReportTitle,omitempty"`
	UpdateSingleBookmarkedTeam                       *UpdateSingleBookmarkedTeamPayload                       `json:"updateSingleBookmarkedTeam,omitempty"`
	UpdateSlackPipeline                              *UpdateSlackPipelinePayload                              `json:"updateSlackPipeline,omitempty"`
	UpdateSlackUser                                  *UpdateSlackUserPayload                                  `json:"updateSlackUser,omitempty"`
	UpdateStructuredPolicy                           *UpdateStructuredPolicyPayload                           `json:"updateStructuredPolicy,omitempty"`
	UpdateStructuredScope                            *UpdateStructuredScopePayload                            `json:"updateStructuredScope,omitempty"`
	UpdateSubmissionRequirements                     *UpdateSubmissionRequirementPayload                      `json:"updateSubmissionRequirements,omitempty"`
	UpdateTeamAllowsPrivateDisclosure                *UpdateTeamAllowsPrivateDisclosurePayload                `json:"updateTeamAllowsPrivateDisclosure,omitempty"`
	UpdateTeamBountySplittingSetting                 *UpdateTeamBountySplittingSettingPayload                 `json:"updateTeamBountySplittingSetting,omitempty"`
	UpdateTeamCriticalSubmissionState                *UpdateTeamCriticalSubmissionStatePayload                `json:"updateTeamCriticalSubmissionState,omitempty"`
	UpdateTeamFancySlackIntegration                  *UpdateTeamFancySlackIntegrationPayload                  `json:"updateTeamFancySlackIntegration,omitempty"`
	UpdateTeamMemberVisibility                       *UpdateTeamMemberVisibilityPayload                       `json:"updateTeamMemberVisibility,omitempty"`
	UpdateTeamResponseSLA                            *UpdateTeamResponseSLAPayload                            `json:"updateTeamResponseSla,omitempty"`
	UpdateTeamSubmissionState                        *UpdateTeamSubmissionStatePayload                        `json:"updateTeamSubmissionState,omitempty"`
	UpdateTeamSubscription                           *UpdateTeamSubscriptionPayload                           `json:"updateTeamSubscription,omitempty"`
	UpdateTeamSuccessGoals                           *UpdateTeamSuccessGoalsPayload                           `json:"updateTeamSuccessGoals,omitempty"`
	UpdateTeamTriageNote                             *UpdateTeamTriageNotePayload                             `json:"updateTeamTriageNote,omitempty"`
	UpdateTeamWeakness                               *UpdateTeamWeaknessPayload                               `json:"updateTeamWeakness,omitempty"`
	UpdateTrigger                                    *UpdateTriggerPayload                                    `json:"updateTrigger,omitempty"`
	UpdateTwoFactorAuthenticationBackupCodes         *UpdateTwoFactorAuthenticationBackupCodesPayload         `json:"updateTwoFactorAuthenticationBackupCodes,omitempty"`
	UpdateTwoFactorAuthenticationCredentials         *UpdateTwoFactorAuthenticationCredentialsPayload         `json:"updateTwoFactorAuthenticationCredentials,omitempty"`
	UpdateUserEmail                                  *UpdateUserEmailPayload                                  `json:"updateUserEmail,omitempty"`
	UpdateUserLufthansaAccount                       *UpdateUserLufthansaAccountPayload                       `json:"updateUserLufthansaAccount,omitempty"`
	UpdateUserPassword                               *UpdateUserPasswordPayload                               `json:"updateUserPassword,omitempty"`
	UpdateUserType                                   *UpdateUserTypePayload                                   `json:"updateUserType,omitempty"`
	Upvote                                           *UpvotePayload                                           `json:"upvote,omitempty"`
	VerifyAccountRecoveryPhoneNumber                 *VerifyAccountRecoveryPhoneNumberPayload                 `json:"verifyAccountRecoveryPhoneNumber,omitempty"`
}

// Autogenerated return type of UpdateUserType
type UpdateUserTypePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

type MutationResult struct {
	Errors                                                 *ErrorConnection                                        `json:"errors,omitempty"`
	WasSuccessful                                          *bool                                                   `json:"was_successful,omitempty"`
	TypeName__                                             string                                                  `json:"__typename,omitempty"`
	AcknowledgeProgramHealthAcknowledgementPayload         *AcknowledgeProgramHealthAcknowledgementPayload         `json:"-"`
	ArchiveStructuredScopePayload                          *ArchiveStructuredScopePayload                          `json:"-"`
	CancelTwoFactorAuthenticationResetPayload              *CancelTwoFactorAuthenticationResetPayload              `json:"-"`
	ClaimCredentialPayload                                 *ClaimCredentialPayload                                 `json:"-"`
	ClaimReportPayload                                     *ClaimReportPayload                                     `json:"-"`
	CompleteReportRetestUserPayload                        *CompleteReportRetestUserPayload                        `json:"-"`
	CreateActivityCommentPayload                           *CreateActivityCommentPayload                           `json:"-"`
	CreateBountyPayload                                    *CreateBountyPayload                                    `json:"-"`
	CreateCoinbasePayoutPreferencePayload                  *CreateCoinbasePayoutPreferencePayload                  `json:"-"`
	CreateCurrencycloudBankTransferPayoutPreferencePayload *CreateCurrencycloudBankTransferPayoutPreferencePayload `json:"-"`
	CreateCVERequestPayload                                *CreateCVERequestPayload                                `json:"-"`
	CreateExternalReportPayload                            *CreateExternalReportPayload                            `json:"-"`
	CreateLeaveProgramSurveyAnswerPayload                  *CreateLeaveProgramSurveyAnswerPayload                  `json:"-"`
	CreateMailingAddressPayload                            *CreateMailingAddressPayload                            `json:"-"`
	CreateOrUpdateJiraIntegrationPayload                   *CreateOrUpdateJiraIntegrationPayload                   `json:"-"`
	CreatePaypalPreferencePayload                          *CreatePaypalPreferencePayload                          `json:"-"`
	CreateRejectionSurveyAnswerPayload                     *CreateRejectionSurveyAnswerPayload                     `json:"-"`
	CreateReportPayload                                    *CreateReportPayload                                    `json:"-"`
	CreateReportSummaryPayload                             *CreateReportSummaryPayload                             `json:"-"`
	CreateSlackPipelinePayload                             *CreateSlackPipelinePayload                             `json:"-"`
	CreateStructuredScopePayload                           *CreateStructuredScopePayload                           `json:"-"`
	CreateTaxFormPayload                                   *CreateTaxFormPayload                                   `json:"-"`
	CreateTriggerPayload                                   *CreateTriggerPayload                                   `json:"-"`
	CreateTwoFactorAuthenticationCredentialsPayload        *CreateTwoFactorAuthenticationCredentialsPayload        `json:"-"`
	CreateUserTwoFactorResetPayload                        *CreateUserTwoFactorResetPayload                        `json:"-"`
	CreateVpnCredentialsPayload                            *CreateVpnCredentialsPayload                            `json:"-"`
	DeleteMailingAddressPayload                            *DeleteMailingAddressPayload                            `json:"-"`
	DeleteSlackPipelinePayload                             *DeleteSlackPipelinePayload                             `json:"-"`
	DeleteTeamMemberPayload                                *DeleteTeamMemberPayload                                `json:"-"`
	DeleteTriggerPayload                                   *DeleteTriggerPayload                                   `json:"-"`
	DeleteUserSessionPayload                               *DeleteUserSessionPayload                               `json:"-"`
	DestroyTwoFactorAuthenticationCredentialsPayload       *DestroyTwoFactorAuthenticationCredentialsPayload       `json:"-"`
	DestroyUpvotePayload                                   *DestroyUpvotePayload                                   `json:"-"`
	DismissProgramHealthAcknowledgementPayload             *DismissProgramHealthAcknowledgementPayload             `json:"-"`
	ExportLifetimeReportsPayload                           *ExportLifetimeReportsPayload                           `json:"-"`
	ForgetFacebookCredentialPayload                        *ForgetFacebookCredentialPayload                        `json:"-"`
	LaunchTeamPayload                                      *LaunchTeamPayload                                      `json:"-"`
	LaunchTeamPubliclyPayload                              *LaunchTeamPubliclyPayload                              `json:"-"`
	LeavePrivateProgramPayload                             *LeavePrivateProgramPayload                             `json:"-"`
	LockReportPayload                                      *LockReportPayload                                      `json:"-"`
	MarkReportAsNeedsMoreInfoPayload                       *MarkReportAsNeedsMoreInfoPayload                       `json:"-"`
	MarkReportAsNoisePayload                               *MarkReportAsNoisePayload                               `json:"-"`
	MarkReportAsSignalPayload                              *MarkReportAsSignalPayload                              `json:"-"`
	ProgramHealthAcknowledgementSeenPayload                *ProgramHealthAcknowledgementSeenPayload                `json:"-"`
	PublishPolicyPayload                                   *PublishPolicyPayload                                   `json:"-"`
	RegenerateCalendarTokenPayload                         *RegenerateCalendarTokenPayload                         `json:"-"`
	RemoveBountyTablePayload                               *RemoveBountyTablePayload                               `json:"-"`
	RevokeCredentialPayload                                *RevokeCredentialPayload                                `json:"-"`
	StartVpnInstancePayload                                *StartVpnInstancePayload                                `json:"-"`
	StopVpnInstancePayload                                 *StopVpnInstancePayload                                 `json:"-"`
	UnclaimReportPayload                                   *UnclaimReportPayload                                   `json:"-"`
	UnsubscribeMailingListPayload                          *UnsubscribeMailingListPayload                          `json:"-"`
	UpdateAccountRecoveryPhoneNumberPayload                *UpdateAccountRecoveryPhoneNumberPayload                `json:"-"`
	UpdateBookmarkedTeamPayload                            *UpdateBookmarkedTeamPayload                            `json:"-"`
	UpdateBountyTablePayload                               *UpdateBountyTablePayload                               `json:"-"`
	UpdateChallengeSettingPayload                          *UpdateChallengeSettingPayload                          `json:"-"`
	UpdateCredentialAccountDetailPayload                   *UpdateCredentialAccountDetailPayload                   `json:"-"`
	UpdateCredentialInstructionPayload                     *UpdateCredentialInstructionPayload                     `json:"-"`
	UpdateCVERequestPayload                                *UpdateCVERequestPayload                                `json:"-"`
	UpdateEmbeddedSubmissionDomainPayload                  *UpdateEmbeddedSubmissionDomainPayload                  `json:"-"`
	UpdateFacebookUserIDPayload                            *UpdateFacebookUserIDPayload                            `json:"-"`
	UpdateInvitationPreferencesPayload                     *UpdateInvitationPreferencesPayload                     `json:"-"`
	UpdateLastViewedNewFeaturesAtPayload                   *UpdateLastViewedNewFeaturesAtPayload                   `json:"-"`
	UpdateMePayload                                        *UpdateMePayload                                        `json:"-"`
	UpdateSingleBookmarkedTeamPayload                      *UpdateSingleBookmarkedTeamPayload                      `json:"-"`
	UpdateStructuredPolicyPayload                          *UpdateStructuredPolicyPayload                          `json:"-"`
	UpdateStructuredScopePayload                           *UpdateStructuredScopePayload                           `json:"-"`
	UpdateSubmissionRequirementPayload                     *UpdateSubmissionRequirementPayload                     `json:"-"`
	UpdateTeamAllowsPrivateDisclosurePayload               *UpdateTeamAllowsPrivateDisclosurePayload               `json:"-"`
	UpdateTeamBountySplittingSettingPayload                *UpdateTeamBountySplittingSettingPayload                `json:"-"`
	UpdateTeamCriticalSubmissionStatePayload               *UpdateTeamCriticalSubmissionStatePayload               `json:"-"`
	UpdateTeamResponseSLAPayload                           *UpdateTeamResponseSLAPayload                           `json:"-"`
	UpdateTeamSuccessGoalsPayload                          *UpdateTeamSuccessGoalsPayload                          `json:"-"`
	UpdateTeamTriageNotePayload                            *UpdateTeamTriageNotePayload                            `json:"-"`
	UpdateTriggerPayload                                   *UpdateTriggerPayload                                   `json:"-"`
	UpdateTwoFactorAuthenticationBackupCodesPayload        *UpdateTwoFactorAuthenticationBackupCodesPayload        `json:"-"`
	UpdateTwoFactorAuthenticationCredentialsPayload        *UpdateTwoFactorAuthenticationCredentialsPayload        `json:"-"`
	UpdateUserEmailPayload                                 *UpdateUserEmailPayload                                 `json:"-"`
	UpdateUserTypePayload                                  *UpdateUserTypePayload                                  `json:"-"`
	UpvotePayload                                          *UpvotePayload                                          `json:"-"`
	VerifyAccountRecoveryPhoneNumberPayload                *VerifyAccountRecoveryPhoneNumberPayload                `json:"-"`
}

func (u *MutationResult) UnmarshalJSON(data []byte) (err error) {
	type tmpType MutationResult
	err = json.Unmarshal(data, (*tmpType)(u))
	if err != nil {
		return err
	}
	var payload interface{}
	switch u.TypeName__ {
	case "AcknowledgeProgramHealthAcknowledgementPayload":
		u.AcknowledgeProgramHealthAcknowledgementPayload = &AcknowledgeProgramHealthAcknowledgementPayload{}
		payload = u.AcknowledgeProgramHealthAcknowledgementPayload
	case "ArchiveStructuredScopePayload":
		u.ArchiveStructuredScopePayload = &ArchiveStructuredScopePayload{}
		payload = u.ArchiveStructuredScopePayload
	case "CancelTwoFactorAuthenticationResetPayload":
		u.CancelTwoFactorAuthenticationResetPayload = &CancelTwoFactorAuthenticationResetPayload{}
		payload = u.CancelTwoFactorAuthenticationResetPayload
	case "ClaimCredentialPayload":
		u.ClaimCredentialPayload = &ClaimCredentialPayload{}
		payload = u.ClaimCredentialPayload
	case "ClaimReportPayload":
		u.ClaimReportPayload = &ClaimReportPayload{}
		payload = u.ClaimReportPayload
	case "CompleteReportRetestUserPayload":
		u.CompleteReportRetestUserPayload = &CompleteReportRetestUserPayload{}
		payload = u.CompleteReportRetestUserPayload
	case "CreateActivityCommentPayload":
		u.CreateActivityCommentPayload = &CreateActivityCommentPayload{}
		payload = u.CreateActivityCommentPayload
	case "CreateBountyPayload":
		u.CreateBountyPayload = &CreateBountyPayload{}
		payload = u.CreateBountyPayload
	case "CreateCoinbasePayoutPreferencePayload":
		u.CreateCoinbasePayoutPreferencePayload = &CreateCoinbasePayoutPreferencePayload{}
		payload = u.CreateCoinbasePayoutPreferencePayload
	case "CreateCurrencycloudBankTransferPayoutPreferencePayload":
		u.CreateCurrencycloudBankTransferPayoutPreferencePayload = &CreateCurrencycloudBankTransferPayoutPreferencePayload{}
		payload = u.CreateCurrencycloudBankTransferPayoutPreferencePayload
	case "CreateCVERequestPayload":
		u.CreateCVERequestPayload = &CreateCVERequestPayload{}
		payload = u.CreateCVERequestPayload
	case "CreateExternalReportPayload":
		u.CreateExternalReportPayload = &CreateExternalReportPayload{}
		payload = u.CreateExternalReportPayload
	case "CreateLeaveProgramSurveyAnswerPayload":
		u.CreateLeaveProgramSurveyAnswerPayload = &CreateLeaveProgramSurveyAnswerPayload{}
		payload = u.CreateLeaveProgramSurveyAnswerPayload
	case "CreateMailingAddressPayload":
		u.CreateMailingAddressPayload = &CreateMailingAddressPayload{}
		payload = u.CreateMailingAddressPayload
	case "CreateOrUpdateJiraIntegrationPayload":
		u.CreateOrUpdateJiraIntegrationPayload = &CreateOrUpdateJiraIntegrationPayload{}
		payload = u.CreateOrUpdateJiraIntegrationPayload
	case "CreatePaypalPreferencePayload":
		u.CreatePaypalPreferencePayload = &CreatePaypalPreferencePayload{}
		payload = u.CreatePaypalPreferencePayload
	case "CreateRejectionSurveyAnswerPayload":
		u.CreateRejectionSurveyAnswerPayload = &CreateRejectionSurveyAnswerPayload{}
		payload = u.CreateRejectionSurveyAnswerPayload
	case "CreateReportPayload":
		u.CreateReportPayload = &CreateReportPayload{}
		payload = u.CreateReportPayload
	case "CreateReportSummaryPayload":
		u.CreateReportSummaryPayload = &CreateReportSummaryPayload{}
		payload = u.CreateReportSummaryPayload
	case "CreateSlackPipelinePayload":
		u.CreateSlackPipelinePayload = &CreateSlackPipelinePayload{}
		payload = u.CreateSlackPipelinePayload
	case "CreateStructuredScopePayload":
		u.CreateStructuredScopePayload = &CreateStructuredScopePayload{}
		payload = u.CreateStructuredScopePayload
	case "CreateTaxFormPayload":
		u.CreateTaxFormPayload = &CreateTaxFormPayload{}
		payload = u.CreateTaxFormPayload
	case "CreateTriggerPayload":
		u.CreateTriggerPayload = &CreateTriggerPayload{}
		payload = u.CreateTriggerPayload
	case "CreateTwoFactorAuthenticationCredentialsPayload":
		u.CreateTwoFactorAuthenticationCredentialsPayload = &CreateTwoFactorAuthenticationCredentialsPayload{}
		payload = u.CreateTwoFactorAuthenticationCredentialsPayload
	case "CreateUserTwoFactorResetPayload":
		u.CreateUserTwoFactorResetPayload = &CreateUserTwoFactorResetPayload{}
		payload = u.CreateUserTwoFactorResetPayload
	case "CreateVpnCredentialsPayload":
		u.CreateVpnCredentialsPayload = &CreateVpnCredentialsPayload{}
		payload = u.CreateVpnCredentialsPayload
	case "DeleteMailingAddressPayload":
		u.DeleteMailingAddressPayload = &DeleteMailingAddressPayload{}
		payload = u.DeleteMailingAddressPayload
	case "DeleteSlackPipelinePayload":
		u.DeleteSlackPipelinePayload = &DeleteSlackPipelinePayload{}
		payload = u.DeleteSlackPipelinePayload
	case "DeleteTeamMemberPayload":
		u.DeleteTeamMemberPayload = &DeleteTeamMemberPayload{}
		payload = u.DeleteTeamMemberPayload
	case "DeleteTriggerPayload":
		u.DeleteTriggerPayload = &DeleteTriggerPayload{}
		payload = u.DeleteTriggerPayload
	case "DeleteUserSessionPayload":
		u.DeleteUserSessionPayload = &DeleteUserSessionPayload{}
		payload = u.DeleteUserSessionPayload
	case "DestroyTwoFactorAuthenticationCredentialsPayload":
		u.DestroyTwoFactorAuthenticationCredentialsPayload = &DestroyTwoFactorAuthenticationCredentialsPayload{}
		payload = u.DestroyTwoFactorAuthenticationCredentialsPayload
	case "DestroyUpvotePayload":
		u.DestroyUpvotePayload = &DestroyUpvotePayload{}
		payload = u.DestroyUpvotePayload
	case "DismissProgramHealthAcknowledgementPayload":
		u.DismissProgramHealthAcknowledgementPayload = &DismissProgramHealthAcknowledgementPayload{}
		payload = u.DismissProgramHealthAcknowledgementPayload
	case "ExportLifetimeReportsPayload":
		u.ExportLifetimeReportsPayload = &ExportLifetimeReportsPayload{}
		payload = u.ExportLifetimeReportsPayload
	case "ForgetFacebookCredentialPayload":
		u.ForgetFacebookCredentialPayload = &ForgetFacebookCredentialPayload{}
		payload = u.ForgetFacebookCredentialPayload
	case "LaunchTeamPayload":
		u.LaunchTeamPayload = &LaunchTeamPayload{}
		payload = u.LaunchTeamPayload
	case "LaunchTeamPubliclyPayload":
		u.LaunchTeamPubliclyPayload = &LaunchTeamPubliclyPayload{}
		payload = u.LaunchTeamPubliclyPayload
	case "LeavePrivateProgramPayload":
		u.LeavePrivateProgramPayload = &LeavePrivateProgramPayload{}
		payload = u.LeavePrivateProgramPayload
	case "LockReportPayload":
		u.LockReportPayload = &LockReportPayload{}
		payload = u.LockReportPayload
	case "MarkReportAsNeedsMoreInfoPayload":
		u.MarkReportAsNeedsMoreInfoPayload = &MarkReportAsNeedsMoreInfoPayload{}
		payload = u.MarkReportAsNeedsMoreInfoPayload
	case "MarkReportAsNoisePayload":
		u.MarkReportAsNoisePayload = &MarkReportAsNoisePayload{}
		payload = u.MarkReportAsNoisePayload
	case "MarkReportAsSignalPayload":
		u.MarkReportAsSignalPayload = &MarkReportAsSignalPayload{}
		payload = u.MarkReportAsSignalPayload
	case "ProgramHealthAcknowledgementSeenPayload":
		u.ProgramHealthAcknowledgementSeenPayload = &ProgramHealthAcknowledgementSeenPayload{}
		payload = u.ProgramHealthAcknowledgementSeenPayload
	case "PublishPolicyPayload":
		u.PublishPolicyPayload = &PublishPolicyPayload{}
		payload = u.PublishPolicyPayload
	case "RegenerateCalendarTokenPayload":
		u.RegenerateCalendarTokenPayload = &RegenerateCalendarTokenPayload{}
		payload = u.RegenerateCalendarTokenPayload
	case "RemoveBountyTablePayload":
		u.RemoveBountyTablePayload = &RemoveBountyTablePayload{}
		payload = u.RemoveBountyTablePayload
	case "RevokeCredentialPayload":
		u.RevokeCredentialPayload = &RevokeCredentialPayload{}
		payload = u.RevokeCredentialPayload
	case "StartVpnInstancePayload":
		u.StartVpnInstancePayload = &StartVpnInstancePayload{}
		payload = u.StartVpnInstancePayload
	case "StopVpnInstancePayload":
		u.StopVpnInstancePayload = &StopVpnInstancePayload{}
		payload = u.StopVpnInstancePayload
	case "UnclaimReportPayload":
		u.UnclaimReportPayload = &UnclaimReportPayload{}
		payload = u.UnclaimReportPayload
	case "UnsubscribeMailingListPayload":
		u.UnsubscribeMailingListPayload = &UnsubscribeMailingListPayload{}
		payload = u.UnsubscribeMailingListPayload
	case "UpdateAccountRecoveryPhoneNumberPayload":
		u.UpdateAccountRecoveryPhoneNumberPayload = &UpdateAccountRecoveryPhoneNumberPayload{}
		payload = u.UpdateAccountRecoveryPhoneNumberPayload
	case "UpdateBookmarkedTeamPayload":
		u.UpdateBookmarkedTeamPayload = &UpdateBookmarkedTeamPayload{}
		payload = u.UpdateBookmarkedTeamPayload
	case "UpdateBountyTablePayload":
		u.UpdateBountyTablePayload = &UpdateBountyTablePayload{}
		payload = u.UpdateBountyTablePayload
	case "UpdateChallengeSettingPayload":
		u.UpdateChallengeSettingPayload = &UpdateChallengeSettingPayload{}
		payload = u.UpdateChallengeSettingPayload
	case "UpdateCredentialAccountDetailPayload":
		u.UpdateCredentialAccountDetailPayload = &UpdateCredentialAccountDetailPayload{}
		payload = u.UpdateCredentialAccountDetailPayload
	case "UpdateCredentialInstructionPayload":
		u.UpdateCredentialInstructionPayload = &UpdateCredentialInstructionPayload{}
		payload = u.UpdateCredentialInstructionPayload
	case "UpdateCVERequestPayload":
		u.UpdateCVERequestPayload = &UpdateCVERequestPayload{}
		payload = u.UpdateCVERequestPayload
	case "UpdateEmbeddedSubmissionDomainPayload":
		u.UpdateEmbeddedSubmissionDomainPayload = &UpdateEmbeddedSubmissionDomainPayload{}
		payload = u.UpdateEmbeddedSubmissionDomainPayload
	case "UpdateFacebookUserIDPayload":
		u.UpdateFacebookUserIDPayload = &UpdateFacebookUserIDPayload{}
		payload = u.UpdateFacebookUserIDPayload
	case "UpdateInvitationPreferencesPayload":
		u.UpdateInvitationPreferencesPayload = &UpdateInvitationPreferencesPayload{}
		payload = u.UpdateInvitationPreferencesPayload
	case "UpdateLastViewedNewFeaturesAtPayload":
		u.UpdateLastViewedNewFeaturesAtPayload = &UpdateLastViewedNewFeaturesAtPayload{}
		payload = u.UpdateLastViewedNewFeaturesAtPayload
	case "UpdateMePayload":
		u.UpdateMePayload = &UpdateMePayload{}
		payload = u.UpdateMePayload
	case "UpdateSingleBookmarkedTeamPayload":
		u.UpdateSingleBookmarkedTeamPayload = &UpdateSingleBookmarkedTeamPayload{}
		payload = u.UpdateSingleBookmarkedTeamPayload
	case "UpdateStructuredPolicyPayload":
		u.UpdateStructuredPolicyPayload = &UpdateStructuredPolicyPayload{}
		payload = u.UpdateStructuredPolicyPayload
	case "UpdateStructuredScopePayload":
		u.UpdateStructuredScopePayload = &UpdateStructuredScopePayload{}
		payload = u.UpdateStructuredScopePayload
	case "UpdateSubmissionRequirementPayload":
		u.UpdateSubmissionRequirementPayload = &UpdateSubmissionRequirementPayload{}
		payload = u.UpdateSubmissionRequirementPayload
	case "UpdateTeamAllowsPrivateDisclosurePayload":
		u.UpdateTeamAllowsPrivateDisclosurePayload = &UpdateTeamAllowsPrivateDisclosurePayload{}
		payload = u.UpdateTeamAllowsPrivateDisclosurePayload
	case "UpdateTeamBountySplittingSettingPayload":
		u.UpdateTeamBountySplittingSettingPayload = &UpdateTeamBountySplittingSettingPayload{}
		payload = u.UpdateTeamBountySplittingSettingPayload
	case "UpdateTeamCriticalSubmissionStatePayload":
		u.UpdateTeamCriticalSubmissionStatePayload = &UpdateTeamCriticalSubmissionStatePayload{}
		payload = u.UpdateTeamCriticalSubmissionStatePayload
	case "UpdateTeamResponseSLAPayload":
		u.UpdateTeamResponseSLAPayload = &UpdateTeamResponseSLAPayload{}
		payload = u.UpdateTeamResponseSLAPayload
	case "UpdateTeamSuccessGoalsPayload":
		u.UpdateTeamSuccessGoalsPayload = &UpdateTeamSuccessGoalsPayload{}
		payload = u.UpdateTeamSuccessGoalsPayload
	case "UpdateTeamTriageNotePayload":
		u.UpdateTeamTriageNotePayload = &UpdateTeamTriageNotePayload{}
		payload = u.UpdateTeamTriageNotePayload
	case "UpdateTriggerPayload":
		u.UpdateTriggerPayload = &UpdateTriggerPayload{}
		payload = u.UpdateTriggerPayload
	case "UpdateTwoFactorAuthenticationBackupCodesPayload":
		u.UpdateTwoFactorAuthenticationBackupCodesPayload = &UpdateTwoFactorAuthenticationBackupCodesPayload{}
		payload = u.UpdateTwoFactorAuthenticationBackupCodesPayload
	case "UpdateTwoFactorAuthenticationCredentialsPayload":
		u.UpdateTwoFactorAuthenticationCredentialsPayload = &UpdateTwoFactorAuthenticationCredentialsPayload{}
		payload = u.UpdateTwoFactorAuthenticationCredentialsPayload
	case "UpdateUserEmailPayload":
		u.UpdateUserEmailPayload = &UpdateUserEmailPayload{}
		payload = u.UpdateUserEmailPayload
	case "UpdateUserTypePayload":
		u.UpdateUserTypePayload = &UpdateUserTypePayload{}
		payload = u.UpdateUserTypePayload
	case "UpvotePayload":
		u.UpvotePayload = &UpvotePayload{}
		payload = u.UpvotePayload
	case "VerifyAccountRecoveryPhoneNumberPayload":
		u.VerifyAccountRecoveryPhoneNumberPayload = &VerifyAccountRecoveryPhoneNumberPayload{}
		payload = u.VerifyAccountRecoveryPhoneNumberPayload
	default:
		return nil
	}
	err = json.Unmarshal(data, payload)
	if err != nil {
		return err
	}
	return nil
}

// The connection type for Error.
type ErrorConnection struct {
	// A list of edges.
	Edges []*ErrorEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*Error `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// An edge in a connection.
type ErrorEdge struct {
	// A cursor for use in pagination.
	Cursor *string `json:"cursor,omitempty"`
	// The item at the end of the edge.
	Node *Error `json:"node,omitempty"`
}

// An error
type Error struct {
	Field   *string        `json:"field,omitempty"`
	ID      *string        `json:"id,omitempty"`
	Message *string        `json:"message,omitempty"`
	Type    *ErrorTypeEnum `json:"type,omitempty"`
}

// Types of errors that can occur
type ErrorTypeEnum string

const (
	ErrorTypeEnumARGUMENT      ErrorTypeEnum = "ARGUMENT"
	ErrorTypeEnumAUTHORIZATION ErrorTypeEnum = "AUTHORIZATION"
	ErrorTypeEnumTHROTTLE      ErrorTypeEnum = "THROTTLE"
)

// Autogenerated input type of UpdateUserType
type UpdateUserTypeInput struct {
	UserType *UserTypeEnum `json:"user_type,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Types a user can be
type UserTypeEnum string

const (
	UserTypeEnumHacker  UserTypeEnum = "hacker"
	UserTypeEnumCompany UserTypeEnum = "company"
	UserTypeEnumLegacy  UserTypeEnum = "legacy"
)

// Autogenerated return type of DestroyUpvote
type DestroyUpvotePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string                  `json:"clientMutationId,omitempty"`
	DeletedVoteID    *string                  `json:"deleted_vote_id,omitempty"`
	Errors           *ErrorConnection         `json:"errors,omitempty"`
	HacktivityItem   *HacktivityItemInterface `json:"hacktivity_item,omitempty"`
	WasSuccessful    *bool                    `json:"was_successful,omitempty"`
}

// Autogenerated input type of DestroyUpvote
type DestroyUpvoteInput struct {
	HacktivityItemID *string `json:"hacktivity_item_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateSingleBookmarkedTeam
type UpdateSingleBookmarkedTeamPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateSingleBookmarkedTeam
type UpdateSingleBookmarkedTeamInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateBookmarkedTeam
type UpdateBookmarkedTeamPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Query            *Query           `json:"query,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateBookmarkedTeam
type UpdateBookmarkedTeamInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ForgetFacebookCredential
type ForgetFacebookCredentialPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ForgetFacebookCredential
type ForgetFacebookCredentialInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateSubmissionRequirement
type UpdateSubmissionRequirementPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateSubmissionRequirement
type UpdateSubmissionRequirementInput struct {
	TeamID        *string `json:"team_id,omitempty"`
	MfaRequiredAt *string `json:"mfa_required_at,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateEmbeddedSubmissionDomain
type UpdateEmbeddedSubmissionDomainPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateEmbeddedSubmissionDomain
type UpdateEmbeddedSubmissionDomainInput struct {
	TeamID                    *string   `json:"team_id,omitempty"`
	EmbeddedSubmissionDomains []*string `json:"embedded_submission_domains,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateCredentialAccountDetail
type UpdateCredentialAccountDetailPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Credential       *Credential      `json:"credential,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateCredentialAccountDetail
type UpdateCredentialAccountDetailInput struct {
	CredentialID   *string `json:"credential_id,omitempty"`
	AccountDetails *string `json:"account_details,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ClaimCredential
type ClaimCredentialPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ClaimCredential
type ClaimCredentialInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateCredentialInstruction
type UpdateCredentialInstructionPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateCredentialInstruction
type UpdateCredentialInstructionInput struct {
	TeamID                *string `json:"team_id,omitempty"`
	CredentialInstruction *string `json:"credential_instruction,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of RemoveBountyTable
type RemoveBountyTablePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of RemoveBountyTable
type RemoveBountyTableInput struct {
	BountyTableID *string `json:"bounty_table_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateBountyTable
type UpdateBountyTablePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateBountyTable
type UpdateBountyTableInput struct {
	TeamID          *string                `json:"team_id,omitempty"`
	BountyTableRows []*BountyTableRowInput `json:"bounty_table_rows,omitempty"`
	LowLabel        *string                `json:"low_label,omitempty"`
	MediumLabel     *string                `json:"medium_label,omitempty"`
	HighLabel       *string                `json:"high_label,omitempty"`
	CriticalLabel   *string                `json:"critical_label,omitempty"`
	Description     *string                `json:"description,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

type BountyTableRowInput struct {
	Destroy           *bool   `json:"destroy,omitempty"`
	ID                *string `json:"id,omitempty"`
	StructuredScopeID *string `json:"structured_scope_id,omitempty"`
	Low               *int32  `json:"low,omitempty"`
	Medium            *int32  `json:"medium,omitempty"`
	High              *int32  `json:"high,omitempty"`
	Critical          *int32  `json:"critical,omitempty"`
	Maximum           *int32  `json:"maximum,omitempty"`
}

// Autogenerated return type of CreateCveRequest
type CreateCVERequestPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string                `json:"clientMutationId,omitempty"`
	CVERequests      *CVERequestsConnection `json:"cve_requests,omitempty"`
	Errors           *ErrorConnection       `json:"errors,omitempty"`
	NewCVERequest    *CVERequestEdge        `json:"new_cve_request,omitempty"`
	Team             *Team                  `json:"team,omitempty"`
	WasSuccessful    *bool                  `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateCveRequest
type CreateCVERequestInput struct {
	RequestType               *string   `json:"request_type,omitempty"`
	TeamHandle                *string   `json:"team_handle,omitempty"`
	Product                   *string   `json:"product,omitempty"`
	ProductVersion            *string   `json:"product_version,omitempty"`
	ReportID                  *int32    `json:"report_id,omitempty"`
	WeaknessName              *string   `json:"weakness_name,omitempty"`
	Description               *string   `json:"description,omitempty"`
	References                []*string `json:"references,omitempty"`
	VulnerabilityDiscoveredAt *string   `json:"vulnerability_discovered_at,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateCveRequest
type UpdateCVERequestPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	CVERequest       *CVERequest      `json:"cve_request,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateCveRequest
type UpdateCVERequestInput struct {
	CVERequestID              *string   `json:"cve_request_id,omitempty"`
	Product                   *string   `json:"product,omitempty"`
	ProductVersion            *string   `json:"product_version,omitempty"`
	ReportID                  *int32    `json:"report_id,omitempty"`
	WeaknessName              *string   `json:"weakness_name,omitempty"`
	Description               *string   `json:"description,omitempty"`
	References                []*string `json:"references,omitempty"`
	VulnerabilityDiscoveredAt *string   `json:"vulnerability_discovered_at,omitempty"`
	Event                     *string   `json:"event,omitempty"`
	EventReason               *string   `json:"event_reason,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteTrigger
type DeleteTriggerPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	DeletedTriggerID *string          `json:"deleted_trigger_id,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DeleteTrigger
type DeleteTriggerInput struct {
	TriggerID *string `json:"trigger_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of RevokeCredential
type RevokeCredentialPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Credential       *Credential      `json:"credential,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of RevokeCredential
type RevokeCredentialInput struct {
	CredentialID *string `json:"credential_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamSuccessGoals
type UpdateTeamSuccessGoalsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamSuccessGoals
type UpdateTeamSuccessGoalsInput struct {
	TeamID           *string `json:"team_id,omitempty"`
	GoalValidReports *int32  `json:"goal_valid_reports,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTrigger
type UpdateTriggerPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Trigger          *Trigger         `json:"trigger,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTrigger
type UpdateTriggerInput struct {
	TriggerID          *string            `json:"trigger_id,omitempty"`
	ActionType         *string            `json:"action_type,omitempty"`
	ActionMessage      *string            `json:"action_message,omitempty"`
	Expressions        []*ExpressionInput `json:"expressions,omitempty"`
	ExpressionOperator *string            `json:"expression_operator,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

type ExpressionInput struct {
	LeftValue  *ExpressionLeftFieldEnum `json:"left_value,omitempty"`
	Operand    *ExpressionOperandEnum   `json:"operand,omitempty"`
	RightValue *string                  `json:"right_value,omitempty"`
}

// Types of left fields that an expression can have
type ExpressionLeftFieldEnum string

const (
	ExpressionLeftFieldEnumReportTitle    ExpressionLeftFieldEnum = "report_title"
	ExpressionLeftFieldEnumAnyField       ExpressionLeftFieldEnum = "any_field"
	ExpressionLeftFieldEnumReportBody     ExpressionLeftFieldEnum = "report_body"
	ExpressionLeftFieldEnumReportWeakness ExpressionLeftFieldEnum = "report_weakness"
)

// Types of operands that an expression can have
type ExpressionOperandEnum string

const (
	ExpressionOperandEnumContains       ExpressionOperandEnum = "contains"
	ExpressionOperandEnumDoesNotContain ExpressionOperandEnum = "does_not_contain"
)

// Autogenerated return type of UpdateChallengeSetting
type UpdateChallengeSettingPayload struct {
	ChallengeSetting *ChallengeSetting `json:"challenge_setting,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateChallengeSetting
type UpdateChallengeSettingInput struct {
	ChallengeSettingID *string `json:"challenge_setting_id,omitempty"`
	Policy             *string `json:"policy,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateTrigger
type CreateTriggerPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string            `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection   `json:"errors,omitempty"`
	NewTrigger       *TriggerEdge       `json:"new_trigger,omitempty"`
	Team             *Team              `json:"team,omitempty"`
	Triggers         *TriggerConnection `json:"triggers,omitempty"`
	WasSuccessful    *bool              `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateTrigger
type CreateTriggerInput struct {
	TeamID             *string            `json:"team_id,omitempty"`
	ActionType         *string            `json:"action_type,omitempty"`
	ActionMessage      *string            `json:"action_message,omitempty"`
	Expressions        []*ExpressionInput `json:"expressions,omitempty"`
	ExpressionOperator *string            `json:"expression_operator,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamTriageNote
type UpdateTeamTriageNotePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamTriageNote
type UpdateTeamTriageNoteInput struct {
	TeamID     *string `json:"team_id,omitempty"`
	TriageNote *string `json:"triage_note,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ProgramHealthAcknowledgementSeen
type ProgramHealthAcknowledgementSeenPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ProgramHealthAcknowledgementSeen
type ProgramHealthAcknowledgementSeenInput struct {
	ProgramHealthAcknowledgementID *string `json:"program_health_acknowledgement_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateLastViewedNewFeaturesAt
type UpdateLastViewedNewFeaturesAtPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateLastViewedNewFeaturesAt
type UpdateLastViewedNewFeaturesAtInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of LeavePrivateProgram
type LeavePrivateProgramPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of LeavePrivateProgram
type LeavePrivateProgramInput struct {
	Handle *string `json:"handle,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ClaimReport
type ClaimReportPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ClaimReport
type ClaimReportInput struct {
	ReportID *string `json:"report_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UnclaimReport
type UnclaimReportPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UnclaimReport
type UnclaimReportInput struct {
	ReportID *string `json:"report_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateVpnCredentials
type CreateVpnCredentialsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateVpnCredentials
type CreateVpnCredentialsInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of StartVpnInstance
type StartVpnInstancePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of StartVpnInstance
type StartVpnInstanceInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of StopVpnInstance
type StopVpnInstancePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of StopVpnInstance
type StopVpnInstanceInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of AcknowledgeProgramHealthAcknowledgement
type AcknowledgeProgramHealthAcknowledgementPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID                      *string          `json:"clientMutationId,omitempty"`
	DeletedProgramHealthAcknowledgementID *string          `json:"deleted_program_health_acknowledgement_id,omitempty"`
	Errors                                *ErrorConnection `json:"errors,omitempty"`
	Me                                    *User            `json:"me,omitempty"`
	WasSuccessful                         *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of AcknowledgeProgramHealthAcknowledgement
type AcknowledgeProgramHealthAcknowledgementInput struct {
	ProgramHealthAcknowledgementID *string `json:"program_health_acknowledgement_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DismissProgramHealthAcknowledgement
type DismissProgramHealthAcknowledgementPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID                      *string          `json:"clientMutationId,omitempty"`
	DeletedProgramHealthAcknowledgementID *string          `json:"deleted_program_health_acknowledgement_id,omitempty"`
	Errors                                *ErrorConnection `json:"errors,omitempty"`
	Me                                    *User            `json:"me,omitempty"`
	WasSuccessful                         *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DismissProgramHealthAcknowledgement
type DismissProgramHealthAcknowledgementInput struct {
	ProgramHealthAcknowledgementID *string `json:"program_health_acknowledgement_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamSubmissionState
type UpdateTeamSubmissionStatePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of UpdateTeamSubmissionState
type UpdateTeamSubmissionStateInput struct {
	Handle          *string              `json:"handle,omitempty"`
	SubmissionState *SubmissionStateEnum `json:"submission_state,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamCriticalSubmissionState
type UpdateTeamCriticalSubmissionStatePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamCriticalSubmissionState
type UpdateTeamCriticalSubmissionStateInput struct {
	Handle                     *string `json:"handle,omitempty"`
	CriticalSubmissionsEnabled *bool   `json:"critical_submissions_enabled,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamResponseSla
type UpdateTeamResponseSLAPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamResponseSla
type UpdateTeamResponseSLAInput struct {
	TeamHandle                                 *string `json:"team_handle,omitempty"`
	NewStalenessThreshold                      *int32  `json:"new_staleness_threshold,omitempty"`
	TriagedStalenessThreshold                  *int32  `json:"triaged_staleness_threshold,omitempty"`
	ResolvedStalenessThreshold                 *int32  `json:"resolved_staleness_threshold,omitempty"`
	BountyAwardedStalenessThreshold            *int32  `json:"bounty_awarded_staleness_threshold,omitempty"`
	UseAdvancedSettings                        *bool   `json:"use_advanced_settings,omitempty"`
	NoneSeverityResolvedStalenessThreshold     *int32  `json:"none_severity_resolved_staleness_threshold,omitempty"`
	LowSeverityResolvedStalenessThreshold      *int32  `json:"low_severity_resolved_staleness_threshold,omitempty"`
	MediumSeverityResolvedStalenessThreshold   *int32  `json:"medium_severity_resolved_staleness_threshold,omitempty"`
	HighSeverityResolvedStalenessThreshold     *int32  `json:"high_severity_resolved_staleness_threshold,omitempty"`
	CriticalSeverityResolvedStalenessThreshold *int32  `json:"critical_severity_resolved_staleness_threshold,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of LockReport
type LockReportPayload struct {
	Activities *ActivityConnection `json:"activities,omitempty"`
	Activity   *ActivitiesComment  `json:"activity,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string            `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection   `json:"errors,omitempty"`
	NewActivity      *ActivityUnionEdge `json:"new_activity,omitempty"`
	Report           *Report            `json:"report,omitempty"`
	WasSuccessful    *bool              `json:"was_successful,omitempty"`
}

// Autogenerated input type of LockReport
type LockReportInput struct {
	ReportID *string `json:"report_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateUserEmail
type UpdateUserEmailPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateUserEmail
type UpdateUserEmailInput struct {
	Email    *string `json:"email,omitempty"`
	Password *string `json:"password,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteTeamMember
type DeleteTeamMemberPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID    *string          `json:"clientMutationId,omitempty"`
	DeletedTeamMemberID *string          `json:"deleted_team_member_id,omitempty"`
	Errors              *ErrorConnection `json:"errors,omitempty"`
	Me                  *User            `json:"me,omitempty"`
	WasSuccessful       *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DeleteTeamMember
type DeleteTeamMemberInput struct {
	TeamMemberID *string `json:"team_member_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateAutomaticInvites
type UpdateAutomaticInvitesPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of UpdateAutomaticInvites
type UpdateAutomaticInvitesInput struct {
	Handle  *string `json:"handle,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateTaxForm
type CreateTaxFormPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateTaxForm
type CreateTaxFormInput struct {
	Type *TaxFormTypeEnum `json:"type,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of GenerateTaxFormUrl
type GenerateTaxFormURLPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of GenerateTaxFormUrl
type GenerateTaxFormURLInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateUserBountiesReport
type CreateUserBountiesReportPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of CreateUserBountiesReport
type CreateUserBountiesReportInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteUserLufthansaAccount
type DeleteUserLufthansaAccountPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of DeleteUserLufthansaAccount
type DeleteUserLufthansaAccountInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateUserLufthansaAccount
type CreateUserLufthansaAccountPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of CreateUserLufthansaAccount
type CreateUserLufthansaAccountInput struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Number    *string `json:"number,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateUserLufthansaAccount
type UpdateUserLufthansaAccountPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of UpdateUserLufthansaAccount
type UpdateUserLufthansaAccountInput struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Number    *string `json:"number,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateSwag
type CreateSwagPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Swag             *Swag   `json:"swag,omitempty"`
}

// Autogenerated input type of CreateSwag
type CreateSwagInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateBountySuggestion
type CreateBountySuggestionPayload struct {
	Activity *ActivitiesBountySuggested `json:"activity,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated input type of CreateBountySuggestion
type CreateBountySuggestionInput struct {
	ReportID    *string  `json:"report_id,omitempty"`
	Message     *string  `json:"message,omitempty"`
	Amount      *float64 `json:"amount,omitempty"`
	BonusAmount *float64 `json:"bonus_amount,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateBounty
type CreateBountyPayload struct {
	Bounty *Bounty `json:"bounty,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateBounty
type CreateBountyInput struct {
	ReportID    *string  `json:"report_id,omitempty"`
	Message     *string  `json:"message,omitempty"`
	Amount      *float64 `json:"amount,omitempty"`
	BonusAmount *float64 `json:"bonus_amount,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateSlackUser
type UpdateSlackUserPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string     `json:"clientMutationId,omitempty"`
	TeamMember       *TeamMember `json:"team_member,omitempty"`
}

// Autogenerated input type of UpdateSlackUser
type UpdateSlackUserInput struct {
	TeamMemberID *string `json:"team_member_id,omitempty"`
	SlackUserID  *string `json:"slack_user_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteSlackPipeline
type DeleteSlackPipelinePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID       *string          `json:"clientMutationId,omitempty"`
	DeletedSlackPipelineID *string          `json:"deleted_slack_pipeline_id,omitempty"`
	Errors                 *ErrorConnection `json:"errors,omitempty"`
	Team                   *Team            `json:"team,omitempty"`
	WasSuccessful          *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DeleteSlackPipeline
type DeleteSlackPipelineInput struct {
	SlackPipelineID *string `json:"slack_pipeline_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateSlackPipeline
type UpdateSlackPipelinePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string        `json:"clientMutationId,omitempty"`
	Errors           *string        `json:"errors,omitempty"`
	SlackPipeline    *SlackPipeline `json:"slack_pipeline,omitempty"`
}

// Autogenerated input type of UpdateSlackPipeline
type UpdateSlackPipelineInput struct {
	SlackPipelineID                        *string `json:"slack_pipeline_id,omitempty"`
	DescriptiveLabel                       *string `json:"descriptive_label,omitempty"`
	Channel                                *string `json:"channel,omitempty"`
	NotificationReportCreated              *bool   `json:"notification_report_created,omitempty"`
	NotificationReportTriaged              *bool   `json:"notification_report_triaged,omitempty"`
	NotificationReportClosedAsResolved     *bool   `json:"notification_report_closed_as_resolved,omitempty"`
	NotificationReportAssigneeChanged      *bool   `json:"notification_report_assignee_changed,omitempty"`
	NotificationReportInternalCommentAdded *bool   `json:"notification_report_internal_comment_added,omitempty"`
	NotificationReportPublicCommentAdded   *bool   `json:"notification_report_public_comment_added,omitempty"`
	NotificationReportBountyPaid           *bool   `json:"notification_report_bounty_paid,omitempty"`
	NotificationReportBountySuggested      *bool   `json:"notification_report_bounty_suggested,omitempty"`
	NotificationReportAgreedOnGoingPublic  *bool   `json:"notification_report_agreed_on_going_public,omitempty"`
	NotificationReportBugDuplicate         *bool   `json:"notification_report_bug_duplicate,omitempty"`
	NotificationReportBugInformative       *bool   `json:"notification_report_bug_informative,omitempty"`
	NotificationReportBugNeedsMoreInfo     *bool   `json:"notification_report_bug_needs_more_info,omitempty"`
	NotificationReportBugNew               *bool   `json:"notification_report_bug_new,omitempty"`
	NotificationReportBugNotApplicable     *bool   `json:"notification_report_bug_not_applicable,omitempty"`
	NotificationReportBugClosedAsSpam      *bool   `json:"notification_report_bug_closed_as_spam,omitempty"`
	NotificationReportCommentsClosed       *bool   `json:"notification_report_comments_closed,omitempty"`
	NotificationReportNotEligibleForBounty *bool   `json:"notification_report_not_eligible_for_bounty,omitempty"`
	NotificationReportBecamePublic         *bool   `json:"notification_report_became_public,omitempty"`
	NotificationReportSwagAwarded          *bool   `json:"notification_report_swag_awarded,omitempty"`
	NotificationReportReopened             *bool   `json:"notification_report_reopened,omitempty"`
	NotificationReportManuallyDisclosed    *bool   `json:"notification_report_manually_disclosed,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateSlackPipeline
type CreateSlackPipelinePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string                  `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection         `json:"errors,omitempty"`
	NewSlackPipeline *SlackPipelineEdge       `json:"new_slack_pipeline,omitempty"`
	SlackPipelines   *SlackPipelineConnection `json:"slack_pipelines,omitempty"`
	Team             *Team                    `json:"team,omitempty"`
	WasSuccessful    *bool                    `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateSlackPipeline
type CreateSlackPipelineInput struct {
	TeamID                                 *string `json:"team_id,omitempty"`
	DescriptiveLabel                       *string `json:"descriptive_label,omitempty"`
	Channel                                *string `json:"channel,omitempty"`
	NotificationReportCreated              *bool   `json:"notification_report_created,omitempty"`
	NotificationReportTriaged              *bool   `json:"notification_report_triaged,omitempty"`
	NotificationReportClosedAsResolved     *bool   `json:"notification_report_closed_as_resolved,omitempty"`
	NotificationReportAssigneeChanged      *bool   `json:"notification_report_assignee_changed,omitempty"`
	NotificationReportInternalCommentAdded *bool   `json:"notification_report_internal_comment_added,omitempty"`
	NotificationReportPublicCommentAdded   *bool   `json:"notification_report_public_comment_added,omitempty"`
	NotificationReportBountyPaid           *bool   `json:"notification_report_bounty_paid,omitempty"`
	NotificationReportBountySuggested      *bool   `json:"notification_report_bounty_suggested,omitempty"`
	NotificationReportAgreedOnGoingPublic  *bool   `json:"notification_report_agreed_on_going_public,omitempty"`
	NotificationReportBugDuplicate         *bool   `json:"notification_report_bug_duplicate,omitempty"`
	NotificationReportBugInformative       *bool   `json:"notification_report_bug_informative,omitempty"`
	NotificationReportBugNeedsMoreInfo     *bool   `json:"notification_report_bug_needs_more_info,omitempty"`
	NotificationReportBugNew               *bool   `json:"notification_report_bug_new,omitempty"`
	NotificationReportBugNotApplicable     *bool   `json:"notification_report_bug_not_applicable,omitempty"`
	NotificationReportBugClosedAsSpam      *bool   `json:"notification_report_bug_closed_as_spam,omitempty"`
	NotificationReportCommentsClosed       *bool   `json:"notification_report_comments_closed,omitempty"`
	NotificationReportNotEligibleForBounty *bool   `json:"notification_report_not_eligible_for_bounty,omitempty"`
	NotificationReportBecamePublic         *bool   `json:"notification_report_became_public,omitempty"`
	NotificationReportSwagAwarded          *bool   `json:"notification_report_swag_awarded,omitempty"`
	NotificationReportReopened             *bool   `json:"notification_report_reopened,omitempty"`
	NotificationReportManuallyDisclosed    *bool   `json:"notification_report_manually_disclosed,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamFancySlackIntegration
type UpdateTeamFancySlackIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of UpdateTeamFancySlackIntegration
type UpdateTeamFancySlackIntegrationInput struct {
	TeamID                *string `json:"team_id,omitempty"`
	FancySlackIntegration *bool   `json:"fancy_slack_integration,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamAllowsPrivateDisclosure
type UpdateTeamAllowsPrivateDisclosurePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamAllowsPrivateDisclosure
type UpdateTeamAllowsPrivateDisclosureInput struct {
	Handle                  *string `json:"handle,omitempty"`
	AllowsPrivateDisclosure *bool   `json:"allows_private_disclosure,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateCurrencycloudBankTransferPayoutPreference
type CreateCurrencycloudBankTransferPayoutPreferencePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateCurrencycloudBankTransferPayoutPreference
type CreateCurrencycloudBankTransferPayoutPreferenceInput struct {
	Currency                   *string                               `json:"currency,omitempty"`
	BankAccountCountry         *string                               `json:"bank_account_country,omitempty"`
	BeneficiaryEntityType      *CurrencycloudBankTransferEntityType  `json:"beneficiary_entity_type,omitempty"`
	BankAccountHolderName      *string                               `json:"bank_account_holder_name,omitempty"`
	BeneficiaryRequiredDetails []*BeneficiaryRequiredDetailInput     `json:"beneficiary_required_details,omitempty"`
	PaymentType                *CurrencycloudBankTransferPaymentType `json:"payment_type,omitempty"`
	DefaultMethod              *bool                                 `json:"default_method,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Different entity types for currencycloud payout preferences
type CurrencycloudBankTransferEntityType string

const (
	CurrencycloudBankTransferEntityTypeCompany    CurrencycloudBankTransferEntityType = "company"
	CurrencycloudBankTransferEntityTypeIndividual CurrencycloudBankTransferEntityType = "individual"
)

type BeneficiaryRequiredDetailInput struct {
	Field *string `json:"field,omitempty"`
	Value *string `json:"value,omitempty"`
}

// Different payment types for currencycloud payout preferences
type CurrencycloudBankTransferPaymentType string

const (
	CurrencycloudBankTransferPaymentTypePriority CurrencycloudBankTransferPaymentType = "priority"
	CurrencycloudBankTransferPaymentTypeRegular  CurrencycloudBankTransferPaymentType = "regular"
)

// Autogenerated return type of CreateCoinbasePayoutPreference
type CreateCoinbasePayoutPreferencePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateCoinbasePayoutPreference
type CreateCoinbasePayoutPreferenceInput struct {
	CoinbaseEmail *string `json:"coinbase_email,omitempty"`
	DefaultMethod *bool   `json:"default_method,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamWeakness
type UpdateTeamWeaknessPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string       `json:"clientMutationId,omitempty"`
	Query            *Query        `json:"query,omitempty"`
	TeamWeakness     *TeamWeakness `json:"team_weakness,omitempty"`
}

// Autogenerated input type of UpdateTeamWeakness
type UpdateTeamWeaknessInput struct {
	TeamWeaknessID *string             `json:"team_weakness_id,omitempty"`
	State          *TeamWeaknessStates `json:"state,omitempty"`
	Instruction    *string             `json:"instruction,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of LaunchTeam
type LaunchTeamPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Sent             *int32           `json:"sent,omitempty"`
	Skipped          *int32           `json:"skipped,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of LaunchTeam
type LaunchTeamInput struct {
	Handle            *string   `json:"handle,omitempty"`
	NewInvites        []*string `json:"new_invites,omitempty"`
	AmountResearchers *int32    `json:"amount_researchers,omitempty"`
	BccMe             *bool     `json:"bcc_me,omitempty"`
	InvitationMessage *string   `json:"invitation_message,omitempty"`
	CancelInvites     *bool     `json:"cancel_invites,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of LaunchTeamPublicly
type LaunchTeamPubliclyPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of LaunchTeamPublicly
type LaunchTeamPubliclyInput struct {
	Handle *string `json:"handle,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateStructuredPolicy
type UpdateStructuredPolicyPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateStructuredPolicy
type UpdateStructuredPolicyInput struct {
	TeamHandle   *string `json:"team_handle,omitempty"`
	BrandPromise *string `json:"brand_promise,omitempty"`
	Scope        *string `json:"scope,omitempty"`
	Process      *string `json:"process,omitempty"`
	SafeHarbor   *string `json:"safe_harbor,omitempty"`
	Preferences  *string `json:"preferences,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateStructuredScope
type UpdateStructuredScopePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	StructuredScope  *StructuredScope `json:"structured_scope,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateStructuredScope
type UpdateStructuredScopeInput struct {
	StructuredScopeID          *string `json:"structured_scope_id,omitempty"`
	AssetIdentifier            *string `json:"asset_identifier,omitempty"`
	EligibleForBounty          *bool   `json:"eligible_for_bounty,omitempty"`
	EligibleForSubmission      *bool   `json:"eligible_for_submission,omitempty"`
	Instruction                *string `json:"instruction,omitempty"`
	AvailabilityRequirement    *string `json:"availability_requirement,omitempty"`
	ConfidentialityRequirement *string `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement       *string `json:"integrity_requirement,omitempty"`
	Reference                  *string `json:"reference,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateStructuredScope
type CreateStructuredScopePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID   *string                    `json:"clientMutationId,omitempty"`
	Errors             *ErrorConnection           `json:"errors,omitempty"`
	NewStructuredScope *StructuredScopeEdge       `json:"new_structured_scope,omitempty"`
	StructuredScopes   *StructuredScopeConnection `json:"structured_scopes,omitempty"`
	Team               *Team                      `json:"team,omitempty"`
	WasSuccessful      *bool                      `json:"was_successful,omitempty"`
}

// The connection type for StructuredScope.
type StructuredScopeConnection struct {
	// A list of edges.
	Edges []*StructuredScopeEdge `json:"edges,omitempty"`
	// A list of nodes.
	Nodes []*StructuredScope `json:"nodes,omitempty"`
	// Information to aid in pagination.
	PageInfo   *PageInfo `json:"pageInfo,omitempty"`
	TotalCount *int32    `json:"total_count,omitempty"`
}

// Autogenerated input type of CreateStructuredScope
type CreateStructuredScopeInput struct {
	TeamID                     *string                       `json:"team_id,omitempty"`
	AssetType                  *StructuredScopeAssetTypeEnum `json:"asset_type,omitempty"`
	AssetIdentifier            *string                       `json:"asset_identifier,omitempty"`
	EligibleForBounty          *bool                         `json:"eligible_for_bounty,omitempty"`
	EligibleForSubmission      *bool                         `json:"eligible_for_submission,omitempty"`
	Instruction                *string                       `json:"instruction,omitempty"`
	AvailabilityRequirement    *string                       `json:"availability_requirement,omitempty"`
	ConfidentialityRequirement *string                       `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement       *string                       `json:"integrity_requirement,omitempty"`
	Reference                  *string                       `json:"reference,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ArchiveStructuredScope
type ArchiveStructuredScopePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	StructuredScope  *StructuredScope `json:"structured_scope,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ArchiveStructuredScope
type ArchiveStructuredScopeInput struct {
	StructuredScopeID *string `json:"structured_scope_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteTeamSlackIntegration
type DeleteTeamSlackIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of DeleteTeamSlackIntegration
type DeleteTeamSlackIntegrationInput struct {
	SlackIntegrationID *string `json:"slack_integration_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdatePhabricatorIntegration
type UpdatePhabricatorIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of UpdatePhabricatorIntegration
type UpdatePhabricatorIntegrationInput struct {
	TeamID                         *string `json:"team_id,omitempty"`
	BaseURL                        *string `json:"base_url,omitempty"`
	ApiToken                       *string `json:"api_token,omitempty"`
	Title                          *string `json:"title,omitempty"`
	Description                    *string `json:"description,omitempty"`
	ProcessH1CommentAdded          *bool   `json:"process_h1_comment_added,omitempty"`
	ProcessH1StatusChange          *bool   `json:"process_h1_status_change,omitempty"`
	ProcessPhabricatorCommentAdded *bool   `json:"process_phabricator_comment_added,omitempty"`
	ProcessPhabricatorStatusChange *bool   `json:"process_phabricator_status_change,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeletePhabricatorIntegration
type DeletePhabricatorIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of DeletePhabricatorIntegration
type DeletePhabricatorIntegrationInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateJiraWebhookToken
type CreateJiraWebhookTokenPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
	WebhookURL       *string `json:"webhook_url,omitempty"`
}

// Autogenerated input type of CreateJiraWebhookToken
type CreateJiraWebhookTokenInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteJiraWebhook
type DeleteJiraWebhookPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of DeleteJiraWebhook
type DeleteJiraWebhookInput struct {
	JiraWebhookID *string `json:"jira_webhook_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteBiDirectionalJiraIntegration
type DeleteBiDirectionalJiraIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of DeleteBiDirectionalJiraIntegration
type DeleteBiDirectionalJiraIntegrationInput struct {
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateJiraOauthUrl
type CreateJiraOauthURLPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Team             *Team   `json:"team,omitempty"`
	URL              *string `json:"url,omitempty"`
}

// Autogenerated input type of CreateJiraOauthUrl
type CreateJiraOauthURLInput struct {
	Site   *string `json:"site,omitempty"`
	TeamID *string `json:"team_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateOrUpdateJiraIntegration
type CreateOrUpdateJiraIntegrationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateOrUpdateJiraIntegration
type CreateOrUpdateJiraIntegrationInput struct {
	TeamID                              *string                    `json:"team_id,omitempty"`
	Pid                                 *int32                     `json:"pid,omitempty"`
	ProjectSelectionEnabled             *bool                      `json:"project_selection_enabled,omitempty"`
	IssueType                           *int32                     `json:"issue_type,omitempty"`
	BaseURL                             *string                    `json:"base_url,omitempty"`
	Summary                             *string                    `json:"summary,omitempty"`
	Description                         *string                    `json:"description,omitempty"`
	Labels                              *string                    `json:"labels,omitempty"`
	Assignee                            *string                    `json:"assignee,omitempty"`
	Custom                              *string                    `json:"custom,omitempty"`
	GenerateWebhookInJiraIfDoesNotExist *bool                      `json:"generate_webhook_in_jira_if_does_not_exist,omitempty"`
	PriorityRatingIds                   *JiraPrioritySeverityInput `json:"priority_rating_ids,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

type JiraPrioritySeverityInput struct {
	None     *string `json:"none,omitempty"`
	Low      *string `json:"low,omitempty"`
	Medium   *string `json:"medium,omitempty"`
	High     *string `json:"high,omitempty"`
	Critical *string `json:"critical,omitempty"`
}

// Autogenerated return type of UpdateJiraWebhook
type UpdateJiraWebhookPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string      `json:"clientMutationId,omitempty"`
	JiraWebhook      *JiraWebhook `json:"jira_webhook,omitempty"`
}

// Autogenerated input type of UpdateJiraWebhook
type UpdateJiraWebhookInput struct {
	JiraWebhookID           *string `json:"jira_webhook_id,omitempty"`
	ProcessAssigneeChange   *bool   `json:"process_assignee_change,omitempty"`
	ProcessCommentAdd       *bool   `json:"process_comment_add,omitempty"`
	ProcessPriorityChange   *bool   `json:"process_priority_change,omitempty"`
	ProcessResolutionChange *bool   `json:"process_resolution_change,omitempty"`
	ProcessStatusChange     *bool   `json:"process_status_change,omitempty"`
	CloseStatusID           *string `json:"close_status_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateOrUpdateHackeroneToJiraEventsConfiguration
type CreateOrUpdateHackeroneToJiraEventsConfigurationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Team             *Team   `json:"team,omitempty"`
}

// Autogenerated input type of CreateOrUpdateHackeroneToJiraEventsConfiguration
type CreateOrUpdateHackeroneToJiraEventsConfigurationInput struct {
	TeamID            *string `json:"team_id,omitempty"`
	Comments          *bool   `json:"comments,omitempty"`
	StateChanges      *bool   `json:"state_changes,omitempty"`
	Rewards           *bool   `json:"rewards,omitempty"`
	AssigneeChanges   *bool   `json:"assignee_changes,omitempty"`
	PublicDisclosures *bool   `json:"public_disclosures,omitempty"`
	Attachments       *bool   `json:"attachments,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreatePaypalPreference
type CreatePaypalPreferencePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreatePaypalPreference
type CreatePaypalPreferenceInput struct {
	PaypalEmail   *string `json:"paypal_email,omitempty"`
	DefaultMethod *bool   `json:"default_method,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportCloseComments
type UpdateReportCloseCommentsPayload struct {
	Activity *ActivitiesCommentsClosed `json:"activity,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated input type of UpdateReportCloseComments
type UpdateReportCloseCommentsInput struct {
	ReportID *string `json:"report_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStructuredScope
type UpdateReportStructuredScopePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStructuredScope
type UpdateReportStructuredScopeInput struct {
	ReportID          *string `json:"report_id,omitempty"`
	StructuredScopeID *string `json:"structured_scope_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportTitle
type UpdateReportTitlePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportTitle
type UpdateReportTitleInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Title    *string `json:"title,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateMe
type UpdateMePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateMe
type UpdateMeInput struct {
	TshirtSize            *string `json:"tshirt_size,omitempty"`
	YearInReviewPublished *bool   `json:"year_in_review_published,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of MarkReportAsSignal
type MarkReportAsSignalPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Query            *Query           `json:"query,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of MarkReportAsSignal
type MarkReportAsSignalInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of MarkReportAsNoise
type MarkReportAsNoisePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Query            *Query           `json:"query,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of MarkReportAsNoise
type MarkReportAsNoiseInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of MarkReportAsNeedsMoreInfo
type MarkReportAsNeedsMoreInfoPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Query            *Query           `json:"query,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of MarkReportAsNeedsMoreInfo
type MarkReportAsNeedsMoreInfoInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateMailingAddress
type CreateMailingAddressPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateMailingAddress
type CreateMailingAddressInput struct {
	Name        *string `json:"name,omitempty"`
	Street      *string `json:"street,omitempty"`
	City        *string `json:"city,omitempty"`
	PostalCode  *string `json:"postal_code,omitempty"`
	State       *string `json:"state,omitempty"`
	Country     *string `json:"country,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteMailingAddress
type DeleteMailingAddressPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DeleteMailingAddress
type DeleteMailingAddressInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToNeedsMoreInfo
type UpdateReportStateToNeedsMoreInfoPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToNeedsMoreInfo
type UpdateReportStateToNeedsMoreInfoInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToNew
type UpdateReportStateToNewPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToNew
type UpdateReportStateToNewInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToTriaged
type UpdateReportStateToTriagedPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToTriaged
type UpdateReportStateToTriagedInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToResolved
type UpdateReportStateToResolvedPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToResolved
type UpdateReportStateToResolvedInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToInformative
type UpdateReportStateToInformativePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToInformative
type UpdateReportStateToInformativeInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToNotApplicable
type UpdateReportStateToNotApplicablePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToNotApplicable
type UpdateReportStateToNotApplicableInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToDuplicate
type UpdateReportStateToDuplicatePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToDuplicate
type UpdateReportStateToDuplicateInput struct {
	ReportID         *string `json:"report_id,omitempty"`
	OriginalReportID *int32  `json:"original_report_id,omitempty"`
	Message          *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateReportStateToSpam
type UpdateReportStateToSpamPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateReportStateToSpam
type UpdateReportStateToSpamInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateAssigneeToUser
type UpdateAssigneeToUserPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateAssigneeToUser
type UpdateAssigneeToUserInput struct {
	ReportID *string `json:"report_id,omitempty"`
	UserID   *string `json:"user_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateAssigneeToGroup
type UpdateAssigneeToGroupPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateAssigneeToGroup
type UpdateAssigneeToGroupInput struct {
	ReportID *string `json:"report_id,omitempty"`
	GroupID  *string `json:"group_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateAssigneeToNobody
type UpdateAssigneeToNobodyPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of UpdateAssigneeToNobody
type UpdateAssigneeToNobodyInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateActivityComment
type CreateActivityCommentPayload struct {
	Activities *ActivityConnection `json:"activities,omitempty"`
	Activity   *ActivitiesComment  `json:"activity,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string            `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection   `json:"errors,omitempty"`
	NewActivity      *ActivityUnionEdge `json:"new_activity,omitempty"`
	Report           *Report            `json:"report,omitempty"`
	WasSuccessful    *bool              `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateActivityComment
type CreateActivityCommentInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Message  *string `json:"message,omitempty"`
	Internal *bool   `json:"internal,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateUserPassword
type UpdateUserPasswordPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of UpdateUserPassword
type UpdateUserPasswordInput struct {
	CurrentPassword      *string `json:"current_password,omitempty"`
	Password             *string `json:"password,omitempty"`
	PasswordConfirmation *string `json:"password_confirmation,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of EnableUser
type EnableUserPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Errors           *string `json:"errors,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of EnableUser
type EnableUserInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateInvitationPreferences
type UpdateInvitationPreferencesPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateInvitationPreferences
type UpdateInvitationPreferencesInput struct {
	InvitationPreference *InvitationPreferenceTypeEnum `json:"invitation_preference,omitempty"`
	ReceiveInvites       *bool                         `json:"receive_invites,omitempty"`
	BountyProgramsOnly   *bool                         `json:"bounty_programs_only,omitempty"`
	ManagedProgramsOnly  *bool                         `json:"managed_programs_only,omitempty"`
	MinBounty            *float64                      `json:"min_bounty,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of RegenerateCalendarToken
type RegenerateCalendarTokenPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of RegenerateCalendarToken
type RegenerateCalendarTokenInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTeamSubscription
type UpdateTeamSubscriptionPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string     `json:"clientMutationId,omitempty"`
	Errors           *string     `json:"errors,omitempty"`
	TeamMember       *TeamMember `json:"team_member,omitempty"`
}

// Autogenerated input type of UpdateTeamSubscription
type UpdateTeamSubscriptionInput struct {
	TeamMemberID  *string                 `json:"team_member_id,omitempty"`
	AutoSubscribe *bool                   `json:"auto_subscribe,omitempty"`
	Action        *SubscriptionActionEnum `json:"action,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Team subscription action enum
type SubscriptionActionEnum string

const (
	SubscriptionActionEnumSubscribeToAll     SubscriptionActionEnum = "subscribe_to_all"
	SubscriptionActionEnumUnsubscribeFromAll SubscriptionActionEnum = "unsubscribe_from_all"
)

// Autogenerated return type of UpdateTeamMemberVisibility
type UpdateTeamMemberVisibilityPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string     `json:"clientMutationId,omitempty"`
	Errors           *string     `json:"errors,omitempty"`
	TeamMember       *TeamMember `json:"team_member,omitempty"`
}

// Autogenerated input type of UpdateTeamMemberVisibility
type UpdateTeamMemberVisibilityInput struct {
	TeamMemberID *string `json:"team_member_id,omitempty"`
	Concealed    *bool   `json:"concealed,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateReport
type CreateReportPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Report           *Report          `json:"report,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateReport
type CreateReportInput struct {
	TeamHandle               *string `json:"team_handle,omitempty"`
	Title                    *string `json:"title,omitempty"`
	VulnerabilityInformation *string `json:"vulnerability_information,omitempty"`
	Severity                 *string `json:"severity,omitempty"`
	AssetIdentifier          *string `json:"asset_identifier,omitempty"`
	FacebookUserID           *string `json:"facebook_user_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of PublishPolicy
type PublishPolicyPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	RedirectPath     *URI             `json:"redirect_path,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of PublishPolicy
type PublishPolicyInput struct {
	Organization             *string `json:"organization,omitempty"`
	Website                  *URI    `json:"website,omitempty"`
	Reason                   *string `json:"reason,omitempty"`
	UserFirstName            *string `json:"user_first_name,omitempty"`
	UserLastName             *string `json:"user_last_name,omitempty"`
	UserEmail                *string `json:"user_email,omitempty"`
	UserPassword             *string `json:"user_password,omitempty"`
	UserPasswordConfirmation *string `json:"user_password_confirmation,omitempty"`
	ReferrerURL              *URI    `json:"referrer_url,omitempty"`
	TeamPolicy               *string `json:"team_policy,omitempty"`
	BrandPromise             *string `json:"brand_promise,omitempty"`
	Scope                    *string `json:"scope,omitempty"`
	Process                  *string `json:"process,omitempty"`
	SafeHarbor               *string `json:"safe_harbor,omitempty"`
	Preferences              *string `json:"preferences,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateReportSummary
type CreateReportSummaryPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	ReportSummary    *Summary         `json:"report_summary,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateReportSummary
type CreateReportSummaryInput struct {
	ReportID *string `json:"report_id,omitempty"`
	Content  *string `json:"content,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateProgramBounty
type CreateProgramBountyPayload struct {
	Bounty *Bounty `json:"bounty,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated input type of CreateProgramBounty
type CreateProgramBountyInput struct {
	ProgramID *string  `json:"program_id,omitempty"`
	Recipient *string  `json:"recipient,omitempty"`
	Title     *string  `json:"title,omitempty"`
	Reference *string  `json:"reference,omitempty"`
	Amount    *float64 `json:"amount,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateIssueTrackerReferenceId
type CreateIssueTrackerReferenceIDPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Report           *Report `json:"report,omitempty"`
}

// Autogenerated input type of CreateIssueTrackerReferenceId
type CreateIssueTrackerReferenceIDInput struct {
	ReportID  *string `json:"report_id,omitempty"`
	Message   *string `json:"message,omitempty"`
	Reference *string `json:"reference,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UnsubscribeMailingList
type UnsubscribeMailingListPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UnsubscribeMailingList
type UnsubscribeMailingListInput struct {
	Subscription *UserEmailSubscriptionEnum `json:"subscription,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// User Email Subscription Enum
type UserEmailSubscriptionEnum string

const (
	UserEmailSubscriptionEnumSubscribedForMonthlyDigest UserEmailSubscriptionEnum = "subscribed_for_monthly_digest"
	UserEmailSubscriptionEnumSubscribedForTeamMessages  UserEmailSubscriptionEnum = "subscribed_for_team_messages"
)

// Autogenerated return type of UpdateTeamBountySplittingSetting
type UpdateTeamBountySplittingSettingPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Team             *Team            `json:"team,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTeamBountySplittingSetting
type UpdateTeamBountySplittingSettingInput struct {
	TeamID                 *string `json:"team_id,omitempty"`
	BountySplittingEnabled *bool   `json:"bounty_splitting_enabled,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of Upvote
type UpvotePayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string                  `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection         `json:"errors,omitempty"`
	HacktivityItem   *HacktivityItemInterface `json:"hacktivity_item,omitempty"`
	NewVote          *VoteEdge                `json:"new_vote,omitempty"`
	Votes            *VoteConnection          `json:"votes,omitempty"`
	WasSuccessful    *bool                    `json:"was_successful,omitempty"`
}

// Autogenerated input type of Upvote
type UpvoteInput struct {
	HacktivityItemID *string `json:"hacktivity_item_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateRejectionSurveyAnswer
type CreateRejectionSurveyAnswerPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateRejectionSurveyAnswer
type CreateRejectionSurveyAnswerInput struct {
	StructuredResponseIds []*string `json:"structured_response_ids,omitempty"`
	Feedback              *string   `json:"feedback,omitempty"`
	InvitationToken       *string   `json:"invitation_token,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateLeaveProgramSurveyAnswer
type CreateLeaveProgramSurveyAnswerPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateLeaveProgramSurveyAnswer
type CreateLeaveProgramSurveyAnswerInput struct {
	StructuredResponseIds []*string `json:"structured_response_ids,omitempty"`
	Feedback              *string   `json:"feedback,omitempty"`
	TeamHandle            *string   `json:"team_handle,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateFacebookUserId
type UpdateFacebookUserIDPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateFacebookUserId
type UpdateFacebookUserIDInput struct {
	FacebookUserID *string `json:"facebook_user_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of AcceptInvitation
type AcceptInvitationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of AcceptInvitation
type AcceptInvitationInput struct {
	Handle *string `json:"handle,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of RejectInvitation
type RejectInvitationPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
	Me               *User   `json:"me,omitempty"`
}

// Autogenerated input type of RejectInvitation
type RejectInvitationInput struct {
	Handle *string `json:"handle,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateExternalReport
type CreateExternalReportPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string           `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection  `json:"errors,omitempty"`
	NewReport        *ReportEdge       `json:"new_report,omitempty"`
	Reports          *ReportConnection `json:"reports,omitempty"`
	Team             *Team             `json:"team,omitempty"`
	WasSuccessful    *bool             `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateExternalReport
type CreateExternalReportInput struct {
	Handle                   *string   `json:"handle,omitempty"`
	HackerRequestedTeamName  *string   `json:"hacker_requested_team_name,omitempty"`
	Title                    *string   `json:"title,omitempty"`
	ReportedDate             *DateTime `json:"reported_date,omitempty"`
	ResolvedDate             *DateTime `json:"resolved_date,omitempty"`
	VulnerabilityInformation *string   `json:"vulnerability_information,omitempty"`
	HackerSummary            *string   `json:"hacker_summary,omitempty"`
	AttachmentIds            []*string `json:"attachment_ids,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of ExportLifetimeReports
type ExportLifetimeReportsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of ExportLifetimeReports
type ExportLifetimeReportsInput struct {
	Handle *string `json:"handle,omitempty"`
	Email  *string `json:"email,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateAccountRecoveryPhoneNumber
type UpdateAccountRecoveryPhoneNumberPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateAccountRecoveryPhoneNumber
type UpdateAccountRecoveryPhoneNumberInput struct {
	AccountRecoveryUnverifiedPhoneNumber *string `json:"account_recovery_unverified_phone_number,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of VerifyAccountRecoveryPhoneNumber
type VerifyAccountRecoveryPhoneNumberPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of VerifyAccountRecoveryPhoneNumber
type VerifyAccountRecoveryPhoneNumberInput struct {
	VerificationCode *string `json:"verification_code,omitempty"`
	OTPCode          *string `json:"otp_code,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateTwoFactorAuthenticationCredentials
type CreateTwoFactorAuthenticationCredentialsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID                   *string                             `json:"clientMutationId,omitempty"`
	Errors                             *ErrorConnection                    `json:"errors,omitempty"`
	Me                                 *User                               `json:"me,omitempty"`
	TwoFactorAuthenticationCredentials *TwoFactorAuthenticationCredentials `json:"two_factor_authentication_credentials,omitempty"`
	WasSuccessful                      *bool                               `json:"was_successful,omitempty"`
}

// An object that holds backup codes, a TOTP secret, signature, and QR code
type TwoFactorAuthenticationCredentials struct {
	BackupCodes []*string `json:"backup_codes,omitempty"`
	ID          *string   `json:"id,omitempty"`
	QrCode      [][]*bool `json:"qr_code,omitempty"`
	Signature   *string   `json:"signature,omitempty"`
	TOTPSecret  *string   `json:"totp_secret,omitempty"`
}

// Autogenerated input type of CreateTwoFactorAuthenticationCredentials
type CreateTwoFactorAuthenticationCredentialsInput struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTwoFactorAuthenticationBackupCodes
type UpdateTwoFactorAuthenticationBackupCodesPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTwoFactorAuthenticationBackupCodes
type UpdateTwoFactorAuthenticationBackupCodesInput struct {
	Password    *string   `json:"password,omitempty"`
	OTPCode     *string   `json:"otp_code,omitempty"`
	TOTPSecret  *string   `json:"totp_secret,omitempty"`
	BackupCode  *string   `json:"backup_code,omitempty"`
	BackupCodes []*string `json:"backup_codes,omitempty"`
	Signature   *string   `json:"signature,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of UpdateTwoFactorAuthenticationCredentials
type UpdateTwoFactorAuthenticationCredentialsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of UpdateTwoFactorAuthenticationCredentials
type UpdateTwoFactorAuthenticationCredentialsInput struct {
	Password    *string   `json:"password,omitempty"`
	OTPCode     *string   `json:"otp_code,omitempty"`
	TOTPSecret  *string   `json:"totp_secret,omitempty"`
	BackupCode  *string   `json:"backup_code,omitempty"`
	BackupCodes []*string `json:"backup_codes,omitempty"`
	Signature   *string   `json:"signature,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DestroyTwoFactorAuthenticationCredentials
type DestroyTwoFactorAuthenticationCredentialsPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Me               *User            `json:"me,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DestroyTwoFactorAuthenticationCredentials
type DestroyTwoFactorAuthenticationCredentialsInput struct {
	Password *string `json:"password,omitempty"`
	OTPCode  *string `json:"otp_code,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CreateUserTwoFactorReset
type CreateUserTwoFactorResetPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Success          *bool            `json:"success,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CreateUserTwoFactorReset
type CreateUserTwoFactorResetInput struct {
	Email       *string `json:"email,omitempty"`
	Password    *string `json:"password,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CancelTwoFactorAuthenticationReset
type CancelTwoFactorAuthenticationResetPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	Success          *bool            `json:"success,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of CancelTwoFactorAuthenticationReset
type CancelTwoFactorAuthenticationResetInput struct {
	Token *string `json:"token,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of CompleteReportRetestUser
type CompleteReportRetestUserPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string           `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection  `json:"errors,omitempty"`
	ReportRetestUser *ReportRetestUser `json:"report_retest_user,omitempty"`
	WasSuccessful    *bool             `json:"was_successful,omitempty"`
}

// Autogenerated input type of CompleteReportRetestUser
type CompleteReportRetestUserInput struct {
	DatabaseReportID         *string   `json:"database_report_id,omitempty"`
	AnsweredCanBeReproduced  *bool     `json:"answered_can_be_reproduced,omitempty"`
	AnsweredFixCanBeBypassed *bool     `json:"answered_fix_can_be_bypassed,omitempty"`
	BypassReportID           *int32    `json:"bypass_report_id,omitempty"`
	Message                  *string   `json:"message,omitempty"`
	AttachmentIds            []*string `json:"attachment_ids,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// Autogenerated return type of DeleteUserSession
type DeleteUserSessionPayload struct {
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string          `json:"clientMutationId,omitempty"`
	Errors           *ErrorConnection `json:"errors,omitempty"`
	UserSession      *UserSession     `json:"user_session,omitempty"`
	WasSuccessful    *bool            `json:"was_successful,omitempty"`
}

// Autogenerated input type of DeleteUserSession
type DeleteUserSessionInput struct {
	UserSessionID *string `json:"user_session_id,omitempty"`
	// A unique identifier for the client performing the mutation.
	ClientMutationID *string `json:"clientMutationId,omitempty"`
}

// A GraphQL Schema defines the capabilities of a GraphQL server. It exposes all available types and directives on the server, as well as the entry points for query, mutation, and subscription operations.
type Schema_ struct {
	// A list of all directives supported by this server.
	Directives []*Directive_ `json:"directives,omitempty"`
	// If this server supports mutation, the type that mutation operations will be rooted at.
	MutationType *Type_ `json:"mutationType,omitempty"`
	// The type that query operations will be rooted at.
	QueryType *Type_ `json:"queryType,omitempty"`
	// If this server support subscription, the type that subscription operations will be rooted at.
	SubscriptionType *Type_ `json:"subscriptionType,omitempty"`
	// A list of all types supported by this server.
	Types []*Type_ `json:"types,omitempty"`
}

// The fundamental unit of any GraphQL Schema is the type. There are many kinds of types in GraphQL as represented by the `__TypeKind` enum.
//
// Depending on the kind of a type, certain fields describe information about that type. Scalar types provide no information beyond a name and description, while Enum types provide their values. Object and Interface types provide the fields they describe. Abstract types, Union and Interface, provide the Object types possible at runtime. List and NonNull types compose other types.
type Type_ struct {
	Description   *string        `json:"description,omitempty"`
	EnumValues    []*EnumValue_  `json:"enumValues,omitempty"`
	Fields        []*Field_      `json:"fields,omitempty"`
	InputFields   []*InputValue_ `json:"inputFields,omitempty"`
	Interfaces    []*Type_       `json:"interfaces,omitempty"`
	Kind          *TypeKind_     `json:"kind,omitempty"`
	Name          *string        `json:"name,omitempty"`
	OfType        *Type_         `json:"ofType,omitempty"`
	PossibleTypes []*Type_       `json:"possibleTypes,omitempty"`
}

// Object and Interface types are described by a list of Fields, each of which has a name, potentially a list of arguments, and a return type.
type Field_ struct {
	Args              []*InputValue_ `json:"args,omitempty"`
	DeprecationReason *string        `json:"deprecationReason,omitempty"`
	Description       *string        `json:"description,omitempty"`
	IsDeprecated      *bool          `json:"isDeprecated,omitempty"`
	Name              *string        `json:"name,omitempty"`
	Type              *Type_         `json:"type,omitempty"`
}

// A Directive provides a way to describe alternate runtime execution and type validation behavior in a GraphQL document.
//
// In some cases, you need to provide options to alter GraphQL's execution behavior in ways field arguments will not suffice, such as conditionally including or skipping a field. Directives provide this by describing additional information to the executor.
type Directive_ struct {
	Args        []*InputValue_        `json:"args,omitempty"`
	Description *string               `json:"description,omitempty"`
	Locations   []*DirectiveLocation_ `json:"locations,omitempty"`
	Name        *string               `json:"name,omitempty"`
	// DEPRECATED: Use `locations`.
	OnField *bool `json:"onField,omitempty"`
	// DEPRECATED: Use `locations`.
	OnFragment *bool `json:"onFragment,omitempty"`
	// DEPRECATED: Use `locations`.
	OnOperation *bool `json:"onOperation,omitempty"`
}

// One possible value for a given Enum. Enum values are unique values, not a placeholder for a string or numeric value. However an Enum value is returned in a JSON response as a string.
type EnumValue_ struct {
	DeprecationReason *string `json:"deprecationReason,omitempty"`
	Description       *string `json:"description,omitempty"`
	IsDeprecated      *bool   `json:"isDeprecated,omitempty"`
	Name              *string `json:"name,omitempty"`
}

// Arguments provided to Fields or Directives and the input fields of an InputObject are represented as Input Values which describe their type and optionally a default value.
type InputValue_ struct {
	// A GraphQL-formatted string representing the default value for this input value.
	DefaultValue *string `json:"defaultValue,omitempty"`
	Description  *string `json:"description,omitempty"`
	Name         *string `json:"name,omitempty"`
	Type         *Type_  `json:"type,omitempty"`
}

// An enum describing what kind of type a given `__Type` is.
type TypeKind_ string

const (
	// Indicates this type is a scalar.
	TypeKind_SCALAR TypeKind_ = "SCALAR"
	// Indicates this type is an object. `fields` and `interfaces` are valid fields.
	TypeKind_OBJECT TypeKind_ = "OBJECT"
	// Indicates this type is an interface. `fields` and `possibleTypes` are valid fields.
	TypeKind_INTERFACE TypeKind_ = "INTERFACE"
	// Indicates this type is a union. `possibleTypes` is a valid field.
	TypeKind_UNION TypeKind_ = "UNION"
	// Indicates this type is an enum. `enumValues` is a valid field.
	TypeKind_ENUM TypeKind_ = "ENUM"
	// Indicates this type is an input object. `inputFields` is a valid field.
	TypeKind_INPUTOBJECT TypeKind_ = "INPUT_OBJECT"
	// Indicates this type is a list. `ofType` is a valid field.
	TypeKind_LIST TypeKind_ = "LIST"
	// Indicates this type is a non-null. `ofType` is a valid field.
	TypeKind_NONNULL TypeKind_ = "NON_NULL"
)

// A Directive can be adjacent to many parts of the GraphQL language, a __DirectiveLocation describes one such possible adjacencies.
type DirectiveLocation_ string

const (
	// Location adjacent to a query operation.
	DirectiveLocation_QUERY DirectiveLocation_ = "QUERY"
	// Location adjacent to a mutation operation.
	DirectiveLocation_MUTATION DirectiveLocation_ = "MUTATION"
	// Location adjacent to a subscription operation.
	DirectiveLocation_SUBSCRIPTION DirectiveLocation_ = "SUBSCRIPTION"
	// Location adjacent to a field.
	DirectiveLocation_FIELD DirectiveLocation_ = "FIELD"
	// Location adjacent to a fragment definition.
	DirectiveLocation_FRAGMENTDEFINITION DirectiveLocation_ = "FRAGMENT_DEFINITION"
	// Location adjacent to a fragment spread.
	DirectiveLocation_FRAGMENTSPREAD DirectiveLocation_ = "FRAGMENT_SPREAD"
	// Location adjacent to an inline fragment.
	DirectiveLocation_INLINEFRAGMENT DirectiveLocation_ = "INLINE_FRAGMENT"
	// Location adjacent to a schema definition.
	DirectiveLocation_SCHEMA DirectiveLocation_ = "SCHEMA"
	// Location adjacent to a scalar definition.
	DirectiveLocation_SCALAR DirectiveLocation_ = "SCALAR"
	// Location adjacent to an object type definition.
	DirectiveLocation_OBJECT DirectiveLocation_ = "OBJECT"
	// Location adjacent to a field definition.
	DirectiveLocation_FIELDDEFINITION DirectiveLocation_ = "FIELD_DEFINITION"
	// Location adjacent to an argument definition.
	DirectiveLocation_ARGUMENTDEFINITION DirectiveLocation_ = "ARGUMENT_DEFINITION"
	// Location adjacent to an interface definition.
	DirectiveLocation_INTERFACE DirectiveLocation_ = "INTERFACE"
	// Location adjacent to a union definition.
	DirectiveLocation_UNION DirectiveLocation_ = "UNION"
	// Location adjacent to an enum definition.
	DirectiveLocation_ENUM DirectiveLocation_ = "ENUM"
	// Location adjacent to an enum value definition.
	DirectiveLocation_ENUMVALUE DirectiveLocation_ = "ENUM_VALUE"
	// Location adjacent to an input object type definition.
	DirectiveLocation_INPUTOBJECT DirectiveLocation_ = "INPUT_OBJECT"
	// Location adjacent to an input object field definition.
	DirectiveLocation_INPUTFIELDDEFINITION DirectiveLocation_ = "INPUT_FIELD_DEFINITION"
)
