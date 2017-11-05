package trust

type Permission interface {
	Name() string
	Match(string) bool
}

type PermissionBase struct {
	id string
}

func NewPermissionBase(id string) *PermissionBase {
	return &PermissionBase{
		id: id,
	}
}

func (t *PermissionBase) Name() string {
	return t.id
}

func (t *PermissionBase) Match(id string) bool {
	return t.id == id
}
