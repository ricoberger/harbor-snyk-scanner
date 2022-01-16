package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSeverity(t *testing.T) {
	require.Equal(t, "critical", getSeverity("critical", "high"))

	require.Equal(t, "high", getSeverity("high", "high"))
	require.Equal(t, "high", getSeverity("high", "medium"))
	require.Equal(t, "critical", getSeverity("high", "critical"))

	require.Equal(t, "medium", getSeverity("medium", "medium"))
	require.Equal(t, "medium", getSeverity("medium", "low"))
	require.Equal(t, "high", getSeverity("medium", "high"))

	require.Equal(t, "low", getSeverity("low", "low"))
	require.Equal(t, "high", getSeverity("low", "high"))

	require.Equal(t, "high", getSeverity("unknown", "high"))
}
