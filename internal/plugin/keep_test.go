package plugin

import "testing"

func TestKeepOld(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]string
		want int
	}{
		{"the Settings value counts the certificate in use", map[string]string{"_keep_total": "3"}, 2},
		{"one means only the one in use", map[string]string{"_keep_total": "1"}, 0},
		{"Settings wins over an old per-target value", map[string]string{"_keep_total": "4", "keep_old": "0"}, 3},
		{"an older caller: the target's own value", map[string]string{"keep_old": "1"}, 1},
		{"nothing set: the earlier default", map[string]string{}, 2},
		{"nonsense is ignored", map[string]string{"_keep_total": "x", "keep_old": "-4"}, 2},
	} {
		if got := KeepOld(tc.cfg); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
