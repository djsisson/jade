package jade

type User struct {
	ID            string  `json:"sub,omitempty"`
	Issuer        string  `json:"iss,omitempty"`
	Name          string  `json:"name,omitempty"`
	Email         string  `json:"email,omitempty"`
	EmailVerified bool    `json:"email_verified,omitempty"`
	FirstName     string  `json:"given_name,omitempty"`
	LastName      string  `json:"family_name,omitempty"`
	MiddleName    string  `json:"middle_name,omitempty"`
	Nickname      string  `json:"nickname,omitempty"`
	UserName      string  `json:"preferred_username,omitempty"`
	Gender        string  `json:"gender,omitempty"`
	Birthdate     string  `json:"birthdate,omitempty"`
	Profile       string  `json:"profile,omitempty"`
	Picture       string  `json:"picture,omitempty"`
	Zoneinfo      string  `json:"zoneinfo,omitempty"`
	Locale        string  `json:"locale,omitempty"`
	UpdatedAt     int64   `json:"updated_at,omitempty"`
	WebSite       string  `json:"website,omitempty"`
	Phone         string  `json:"phone_number,omitempty"`
	Address       Address `json:"address"`
}

type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}
