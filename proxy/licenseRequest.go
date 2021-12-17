package widevineproxy

type Message struct {
	Payload                       string           `json:"payload"`
	Provider                      string           `json:"provider"`
	ContentID                     string           `json:"content_id"`
	AllowedTrackTypes             AllowedTrackType `json:"allowed_track_types"`
	ContentKeySpecs               []ContentKeySpec `json:"content_key_specs"`
	SDOnlyForL3                   bool             `json:"sd_only_for_l3,omitempty"`
	PolicyOverrides               *PolicyOverrides `json:"policy_overrides,omitempty"`
	UsePolicyOverridesExclusively bool             `json:"use_policy_overrides_exclusively,omitempty"`
	ParseOnly                     bool             `json:"parse_only,omitempty"`
	SessionInit                   *SessionInit     `json:"session_init,omitempty"`
	SessionKey                    string           `json:"session_key,omitempty"`
	SessionIV                     string           `json:"session_iv,omitempty"`
	ClientIDMsg                   string           `json:"client_id_msg,omitempty"`
	AllowUnVerifiedPlatform       bool             `json:"allow_unverified_platform,omitempty"`
}

type AllowedTrackType string

const (
	AllowedTrackTypeSD   AllowedTrackType = "SD_ONLY"
	AllowedTrackTypeHD                    = "SD_HD"
	AllowedTrackTypeUHD1                  = "SD_UHD1"
	AllowedTrackTypeUHD2                  = "SD_UHD2"
)

type ContentKeySpec struct {
	TrackType        ContentTrackType `json:"track_type"`
	SecurityLevel    SecurityLevel    `json:"security_level" default:"1"`
	KeyID            string           `json:"key_id"`
	Key              string           `json:"key"`
	IV               string           `json:"iv,omitempty"`
	OutputProtection OutputProtection `json:"required_output_protection"`
}

type ContentTrackType string

const (
	ContentTrackTypeAudio ContentTrackType = "AUDIO"
	ContentTrackTypeSD                     = "SD"
	ContentTrackTypeHD                     = "HD"
	ContentTrackTypeUHD1                   = "UHD1"
	ContentTrackTypeUHD2                   = "UHD2"
)

type SecurityLevel uint32

const (
	SecurityLevelSoftwareSecureCrypto SecurityLevel = 1 // Software-based whitebox crypto is required.
	SecurityLevelSoftwareSecureDecode               = 2 // Software crypto and an obfuscated decoder is required.
	SecurityLevelHardwareSecureCrypto               = 3 // The key material and crypto operations must be performed within a hardware backed trusted execution environment.
	SecurityLevelHardwareSecureDecode               = 4 // The crypto and decoding of content must be performed within a hardware backed trusted execution environment.
	SecurityLevelHardwareSecureAll                  = 5 // The crypto, decoding and all handling of the media (compressed and uncompressed) must be handled within a hardware backed trusted execution environment.
)

type OutputProtection struct {
	CGMSFlags           CGMSFlagsType `json:"cgms_flags"`
	DisableAnalogOutput bool          `json:"disable_analog_output"`
	HDCP                HDCPVersion   `json:"hdcp"`
	HDCPSrmRule         HDCPSrmRule   `json:"hdcp_srm_rule"`
}

type CGMSFlagsType string

const (
	CGMSFlagsTypeNone      CGMSFlagsType = "CGMS_NONE" // Default
	CGMSFlagsTypeCopyFree                = "COPY_FREE"
	CGMSFlagsTypeCopyOnce                = "COPY_ONCE"
	CGMSFlagsTypeCopyNever               = "COPY_NEVER"
)

type HDCPVersion string

const (
	HDCPVersionNone           HDCPVersion = "HDCP_NONE" // Default
	HDCPVersionV1                         = "HDCP_V1"
	HDCPVersionV2                         = "HDCP_V2"
	HDCPVersionV2d1                       = "HDCP_V2_1"
	HDCPVersionV2d2                       = "HDCP_V2_2"
	HDCPVersionNoDigtalOutput             = "HDCP_NO_DIGITAL_OUTPUT"
)

type HDCPSrmRule string

const (
	HDCPSrmRuleNone    HDCPSrmRule = "HDCP_SRM_RULE_NONE" // Default
	HDCPSrmRuleCurrent             = "CURRENT_SRM"
)

type PolicyOverrides struct {
	CanPlay                        bool   `json:"can_play" default:"true"`                     // Default: false; Indicates that playback of the content is allowed.
	CanPersist                     bool   `json:"can_persist,omitempty"`                       // Default: false; Indicates that the license may be persisted to non-volatile storage for offline use.
	CanRenew                       bool   `json:"can_renew,omitempty"`                         // Default: false; Indicates that renewal of this license is allowed. If true, the duration of the license can be extended by heartbeat.
	LicenseDurationSeconds         uint64 `json:"license_duration_seconds,omitempty"`          // Default: 0; Indicates the time window for this specific license. A value of 0 indicates unlimited.
	RentalDurationSeconds          uint64 `json:"rental_duration_seconds,omitempty"`           // Default: 0; Indicates the time window while playback is permitted. A value of 0 indicates unlimited.
	PlaybackDurationSeconds        uint64 `json:"playback_duration_seconds,omitempty"`         // Default: 0; The viewing window of time once playback starts within the license duration. A value of 0 indicates unlimited.
	TimeShiftLimitSeconds          uint64 `json:"time_shift_limit_seconds,omitempty"`          // Default: 0; Indicates the allowed delay between the time the content was transmitted and the time the content is viewed. A value of 0 indicates unlimited.
	RenewalServerUrl               string `json:"renewal_server_url,omitempty"`                // Default: ""; All heartbeat (renewal) requests for this license shall be directed to the specified URL. This field is only used if can_renew is true.
	RenewalDelaySeconds            uint64 `json:"renewal_delay_seconds,omitempty"`             // Default: 0; How many seconds after license_start_time, before renewal is first attempted. This field is only used if can_renew is true.
	RenewalRetryIntervalSeconds    uint64 `json:"renewal_retry_interval_seconds,omitempty"`    // Default: 0; Specifies the delay in seconds between subsequent license renewal requests, in case of failure. This field is only used if can_renew is true.
	RenewalRecoveryDurationSeconds uint64 `json:"renewal_recovery_duration_seconds,omitempty"` // Default: 0; The window of time, in which playback is allowed to continue while renewal is attempted, yet unsuccessful due to backend problems with the license server. ​A value of 0 indicates unlimited. This field is only used if can_renew is true.
	RenewWithUsage                 bool   `json:"renew_with_usage,omitempty"`                  // Default: false; Indicates that the license shall be sent for renewal when usage is started. ​This field is only used if can_renew is true.
	AlwaysIncludeClientId          bool   `json:"always_include_client_id,omitempty"`          // Default: false; Indicates to clients that license renewal and release requests must include client identification (client_id).
}

type SessionInit struct {
	ProviderClientToken         string `json:"provider_client_token"`          // provider_client_token​ is only supported in the Chrome CDM and ​persistentState​ must be enabled by the Application.
	OverrideProviderClientToken bool   `json:"override_provider_client_token"` // Default: false;
	SessionID                   string `json:"session_id"`                     // Identify the session. This value will exist in all subsequent license renewals​ associated with this license.
}
