package auth

// ResourceID to identify Resources.
type ResourceID string

// ResourceKind to get the type of a Resource.
type ResourceKind string

// Resource is an interface that must be implemented by entities.
type Resource interface {
	Identifier() (id ResourceID)
	Kind() (kind ResourceKind)
}

// resourceImpl is an internally-used type that implements Resource. It is handy
// in persisting Resources.
type resourceImpl struct {
	kind ResourceKind
	id   ResourceID
}

func (res resourceImpl) Identifier() (id ResourceID) {
	return res.id
}

func (res resourceImpl) Kind() (kind ResourceKind) {
	return res.kind
}

// PlatformResource is the top level Resource that contains all other Resources.
var PlatformResource = resourceImpl{
	id:   ResourceID("*"),
	kind: ResourceKind("platform"),
}
