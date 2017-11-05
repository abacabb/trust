package trust

import (
	"sync"
)

const ErrRoleNotExists = Error("role does not exists")

type PermissionFunc func(permission string) bool

type Manager struct {
	sync.RWMutex
	roles map[string]Role
}

func NewManager() *Manager {
	return &Manager{
		roles: make(map[string]Role, 1),
	}
}

func (t *Manager) Can(permission string, roles []string) bool {
	for _, name := range roles {
		if role, ok := t.roles[name]; ok {
			return role.Permit(permission)
		}
	}

	return false
}

// permissions - permissions checked
// roles - user roles
// f -
func (t *Manager) CanF(permission string, roles []string, f PermissionFunc) bool {
	for _, name := range roles {
		if role, ok := t.roles[name]; ok {
			return role.Permit(permission) && f(permission)
		}
	}

	return false
}

func (t *Manager) AddRole(r Role) {
	t.roles[r.Name()] = r
}

func (t *Manager) RemoveRole(id string){
	delete(t.roles, id)
}

func (t *Manager) FindRole(id string) (Role, error) {
	if role, ok := t.roles[id]; ok {
		return role, nil
	}

	return nil, ErrRoleNotExists
}

func (t *Manager) Roles() map[string]Role {
	return  t.roles
}