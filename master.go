package auth

var master User = userImpl{
	id:     "not set",
	secret: "not set",
}

// ConfigMaster sets the details for the user that has access to everything
func ConfigMaster(id string, secret string) {
	master = userImpl{
		id:     id,
		secret: secret,
	}
}

type userImpl struct {
	id     string
	secret string
}

func (m userImpl) GetID() string {
	return m.id
}

func (m userImpl) GetSecret() string {
	return m.secret
}

func (m userImpl) GetIsVerified() bool {
	return true
}
