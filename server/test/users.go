package test

import (
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
)

var (
	GoodPassword  = "password123#"
	GoodPassword2 = "password123!"
	UserNoRoles   = &mobius.User{
		ID: 1,
	}
	UserAdmin = &mobius.User{
		ID:         2,
		GlobalRole: ptr.String(mobius.RoleAdmin),
		Email:      "useradmin@example.com",
	}
	UserMaintainer = &mobius.User{
		ID:         3,
		GlobalRole: ptr.String(mobius.RoleMaintainer),
	}
	UserObserver = &mobius.User{
		ID:         4,
		GlobalRole: ptr.String(mobius.RoleObserver),
	}
	UserTeamAdminTeam1 = &mobius.User{
		ID: 5,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleAdmin,
			},
		},
	}
	UserTeamAdminTeam2 = &mobius.User{
		ID: 6,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleAdmin,
			},
		},
	}
	UserTeamMaintainerTeam1 = &mobius.User{
		ID: 7,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleMaintainer,
			},
		},
	}
	UserTeamMaintainerTeam2 = &mobius.User{
		ID: 8,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleMaintainer,
			},
		},
	}
	UserTeamObserverTeam1 = &mobius.User{
		ID: 9,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleObserver,
			},
		},
	}
	UserTeamObserverTeam2 = &mobius.User{
		ID: 10,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleObserver,
			},
		},
	}
	UserTeamObserverTeam1TeamAdminTeam2 = &mobius.User{
		ID: 11,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleObserver,
			},
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleAdmin,
			},
		},
	}
	UserObserverPlus = &mobius.User{
		ID:         12,
		GlobalRole: ptr.String(mobius.RoleObserverPlus),
	}
	UserTeamObserverPlusTeam1 = &mobius.User{
		ID: 13,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleObserverPlus,
			},
		},
	}
	UserTeamObserverPlusTeam2 = &mobius.User{
		ID: 14,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleObserverPlus,
			},
		},
	}
	UserGitOps = &mobius.User{
		ID:         15,
		GlobalRole: ptr.String(mobius.RoleGitOps),
	}
	UserTeamGitOpsTeam1 = &mobius.User{
		ID: 16,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleGitOps,
			},
		},
	}
	UserTeamGitOpsTeam2 = &mobius.User{
		ID: 17,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleGitOps,
			},
		},
	}
)
