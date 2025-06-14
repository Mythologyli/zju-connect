package auth

type Cookie struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type ClientAuthData struct {
	Cookies      []Cookie `json:"cookies"`
	DeviceID     string   `json:"device_id"`
	ConnectionID string   `json:"connection_id"`
}
