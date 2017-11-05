package trust

const ErrRoleAlreadyAttached = Error("role already attached to role")
const ErrRecursiveRoleDetectLoop = Error("recursive attached role detect loop")
const ErrBadAttachedRoleName = Error("parent role already has same name")

type Recursively interface {
	Roles() []Role
}

type RoleH struct {
	RoleB
	roles []Role
}

func NewRoleHierarchy(name string) *RoleH {
	return &RoleH{
		RoleB: *NewRoleBase(name),
		roles: make([]Role, 0),
	}
}

func (t *RoleH) Permit(permission string) bool {
	for _, p := range t.permissions {
		if p.Match(permission) {
			return true
		}
	}

	for _, r := range t.roles {
		if r.Permit(permission) {
			return true
		}
	}

	return false
}

func (t *RoleH) Roles() []Role  {
	return t.roles
}

func (t *RoleH) AttachRole(r Role) error {
	t.Lock()
	defer t.Unlock()

	err := t.check(r)
	if err != nil {
		return err
	}

	t.roles = append(t.roles, r)

	return nil
}

func (t *RoleH) check(r Role) error {

	var err error
	if t.name == r.Name() {
		return ErrBadAttachedRoleName
	}

	for _, v := range t.roles {
		if v.Name() == r.Name() {
			return ErrRoleAlreadyAttached
		}
		if recursive, ok := v.(Recursively); ok {
			if err = t.detectLoop(r.Name(), recursive.Roles()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t *RoleH) detectLoop(role string, parents []Role) error {

	for _, p := range parents {
		if role == p.Name() {
			return ErrRecursiveRoleDetectLoop
		}
		if recursive, ok := p.(Recursively); ok {
			if err := t.detectLoop(role, recursive.Roles()); err != nil {
				return err
			}
		}
	}

	return nil
}