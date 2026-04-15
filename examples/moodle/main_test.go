package main

import "testing"

func TestHasLearnerRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{
			name: "full learner role uri",
			roles: []string{
				"http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
			},
			want: true,
		},
		{
			name: "plain learner role",
			roles: []string{
				"Learner",
			},
			want: true,
		},
		{
			name: "non learner role",
			roles: []string{
				"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
			},
			want: false,
		},
		{
			name: "mixed roles",
			roles: []string{
				"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
				"http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasLearnerRole(tt.roles); got != tt.want {
				t.Fatalf("hasLearnerRole(%v) = %v, want %v", tt.roles, got, tt.want)
			}
		})
	}
}
