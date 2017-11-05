package trust

import (
	"sync"
)

const ErrPermissionAlreadyAssigned = Error("permission already assigned to role")

type Role interface {
	Name() string
	Permit(string) bool
}

type Permissions interface {
	Permissions() []Permission
}

type RoleB struct {
	sync.RWMutex
	name        string
	permissions map[string]Permission
}

func NewRoleBase(name string) *RoleB {
	return &RoleB{
		name:          name,
		permissions: make(map[string]Permission, 0),
	}
}

func (t *RoleB) Name() string {
	return t.name
}

func (t *RoleB) Permit(permission string) bool {
	t.RLock()
	defer t.RUnlock()

	for _, p := range t.permissions {
		if p.Match(permission) {
			return true
		}
	}

	return false
}

func (t *RoleB) Permissions() []Permission {
	t.RLock()
	defer t.RUnlock()

	result := make([]Permission, len(t.permissions))
	for _, p := range t.permissions {
		result = append(result, p)
	}

	return result
}

func (t *RoleB) Assign(p Permission) error {
	t.Lock()
	defer t.Unlock()

	if _, ok := t.permissions[p.Name()]; ok {
		return ErrPermissionAlreadyAssigned
	}
	t.permissions[p.Name()] = p

	return nil
}

func (t *RoleB) Revoke(permission string) {
	t.Lock()
	defer t.Unlock()
	delete(t.permissions, permission)
}
