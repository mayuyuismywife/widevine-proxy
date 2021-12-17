package widevineproxy

// LicenseResponse decoded JSON response from Widevine Cloud.
// /cenc/getlicense
type LicenseResponse struct {
	Status                     string             `json:"status"`
	StatusMessage              string             `json:"status_message"`
	License                    string             `json:"license"`
	LicenseMetadata            LicenseMetadata    `json:"license_metadata"`
	SupportedTracks            []interface{}      `json:"supported_tracks"`
	Make                       string             `json:"make"`
	Model                      string             `json:"model"`
	SecurityLevel              int64              `json:"security_level"`
	InternalStatus             int64              `json:"internal_status"`
	SessionState               SessionState       `json:"session_state"`
	DRMCERTSerialNumber        string             `json:"drm_cert_serial_number"`
	DeviceWhitelistState       string             `json:"device_whitelist_state"`
	MessageType                string             `json:"message_type"`
	Platform                   string             `json:"platform"`
	DeviceState                string             `json:"device_state"`
	PsshData                   PsshData           `json:"pssh_data"`
	ClientMaxHdcpVersion       string             `json:"client_max_hdcp_version"`
	ClientInfo                 []ClientInfo       `json:"client_info"`
	SignatureExpirationSecs    int64              `json:"signature_expiration_secs"`
	PlatformVerificationStatus string             `json:"platform_verification_status"`
	ContentOwner               string             `json:"content_owner"`
	ContentProvider            string             `json:"content_provider"`
	SystemID                   int64              `json:"system_id"`
	OEMCryptoAPIVersion        int64              `json:"oem_crypto_api_version"`
	ResourceRatingTier         int64              `json:"resource_rating_tier"`
	ServiceVersionInfo         ServiceVersionInfo `json:"service_version_info"`
}

type ClientInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type LicenseMetadata struct {
	ContentID   string `json:"content_id"`
	LicenseType string `json:"license_type"`
	RequestType string `json:"request_type"`
}

type PsshData struct {
	KeyID     []string `json:"key_id"`
	ContentID string   `json:"content_id"`
}

type ServiceVersionInfo struct {
	LicenseSDKVersion     string `json:"license_sdk_version"`
	LicenseServiceVersion string `json:"license_service_version"`
}

type SessionState struct {
	LicenseID      LicenseID `json:"license_id"`
	SigningKey     string    `json:"signing_key"`
	KeyboxSystemID int64     `json:"keybox_system_id"`
	LicenseCounter int64     `json:"license_counter"`
}

type LicenseID struct {
	RequestID  string `json:"request_id"`
	SessionID  string `json:"session_id"`
	PurchaseID string `json:"purchase_id"`
	Type       string `json:"type"`
	Version    int64  `json:"version"`
}

type LicenseMessage struct {
	Payload           string           `json:"payload"`
	ContentID         string           `json:"content_id"`
	Provider          string           `json:"provider"`
	AllowedTrackTypes string           `json:"allowed_track_types"`
	ContentKeySpecs   []ContentKeySpec `json:"content_key_specs"`
}
