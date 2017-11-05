package trust

import "testing"

var _ Role = &RoleB{}
var _ Role = &RoleH{}

func TestBaseRole(t *testing.T) {
	r := NewRoleBase("role-x")
	if r.Name() != "role-x" {
		t.Fatal("RoleB Name not equals")
	}

	if r.Permit("role-x") {
		t.Fatal("RoleB: role does not nave access by role name")
	}

	p1 := NewPermissionBase("perm-1")
	p2 := NewPermissionBase("perm-2")
	err := r.Assign(p1)
	if err != nil {
		t.Fatal(err)
	}
	err = r.Assign(p2)
	if err != nil {
		t.Fatal(err)
	}

	if !r.Permit("perm-1") {
		t.Fatal("RoleB: role must have permission")
	}

	if r.Permit("perm-3") {
		t.Fatal("RoleB: role has access by no permission")
	}
}
