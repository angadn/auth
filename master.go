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

// IsMaster is a convenience-method to check whether the User is Master or not.
func IsMaster(id, secret string) (ok bool) {
	if ok = id == master.GetID(); !ok {
		return
	}

	if ok = secret == master.GetSecret(); !ok {
		return
	}

	return
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
