package trust

import (
	"testing"
)

func TestHierarchyRole(t *testing.T) {

	r := NewRoleHierarchy("role-x")
	if r.Name() != "role-x" {
		t.Fatal("RoleH ")
	}

	r1 := NewRoleHierarchy("role-1")
	r2 := NewRoleHierarchy("role-2")
	r.AttachRole(r1)
	r.AttachRole(r2)

	r21 := NewRoleHierarchy("role-2-1")
	p21 := NewPermissionBase("perm-2-1")
	r21.Assign(p21)
	r2.AttachRole(r21)

	if !r.Permit("perm-2-1") {
		t.Fatal("RoleH: parent does not have role child > child role")
	}
	if r.Permit("role-2-2") {
		t.Fatal("RoleH: has some role")
	}

	p := NewPermissionBase("perm-1")
	r.Assign(p)
	if !r.Permit("perm-1") {
		t.Fatal("RoleH: cant find permission")
	}

	p1 := NewPermissionBase("perm-2-1[1]")
	p2 := NewPermissionBase("perm-2-1[2]")
	r21.Assign(p1)
	r21.Assign(p2)

	if !r.Permit("perm-2-1[1]") {
		t.Fatal("RoleH: perm not found")
	}
}

func TestHierarchyRoleErrors(t *testing.T) {
	r := NewRoleHierarchy("role")
	r1 := NewRoleHierarchy("role-1")
	r2 := NewRoleHierarchy("role-2")
	r.AttachRole(r1)
	r.AttachRole(r2)

	r1Bad := NewRoleBase("role-1")
	err := r.AttachRole(r1Bad)
	if err != ErrRoleAlreadyAttached {
		t.Fatal("role must have an assigned role")
	}

	r21 := NewRoleBase("role")
	err = r2.AttachRole(r21)
	if err != ErrRecursiveRoleDetectLoop {
		t.Fatal("role must have a loop")
	}
}
