// Package spec contains functionality to parse "Mobius specs" yaml files
// (which are concatenated yaml files) that can be applied to a Mobius server.
package spec

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/ghodss/yaml"
	"github.com/hashicorp/go-multierror"
)

var yamlSeparator = regexp.MustCompile(`(?m:^---[\t ]*)`)

// Group holds a set of "specs" that can be applied to a Mobius server.
type Group struct {
	Queries  []*mobius.QuerySpec
	Teams    []json.RawMessage
	Packs    []*mobius.PackSpec
	Labels   []*mobius.LabelSpec
	Policies []*mobius.PolicySpec
	Software []*mobius.SoftwarePackageSpec
	// This needs to be interface{} to allow for the patch logic. Otherwise we send a request that looks to the
	// server like the user explicitly set the zero values.
	AppConfig              interface{}
	EnrollSecret           *mobius.EnrollSecretSpec
	UsersRoles             *mobius.UsersRoleSpec
	TeamsDryRunAssumptions *mobius.TeamSpecsDryRunAssumptions
}

// Metadata holds the metadata for a single YAML section/item.
type Metadata struct {
	Kind    string          `json:"kind"`
	Version string          `json:"apiVersion"`
	Spec    json.RawMessage `json:"spec"`
}

// GroupFromBytes parses a Group from concatenated YAML specs.
func GroupFromBytes(b []byte) (*Group, error) {
	specs := &Group{}
	for _, specItem := range SplitYaml(string(b)) {
		var s Metadata
		if err := yaml.Unmarshal([]byte(specItem), &s); err != nil {
			return nil, fmt.Errorf("failed to unmarshal spec item %w: \n%s", err, specItem)
		}

		kind := strings.ToLower(s.Kind)

		if s.Spec == nil {
			if kind == "" {
				return nil, errors.New(`Missing required fields ("spec", "kind") on provided configuration.`)
			}
			return nil, fmt.Errorf(`Missing required fields ("spec") on provided %q configuration.`, s.Kind)
		}

		switch kind {
		case mobius.QueryKind:
			var querySpec *mobius.QuerySpec
			if err := yaml.Unmarshal(s.Spec, &querySpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.Queries = append(specs.Queries, querySpec)

		case mobius.PackKind:
			var packSpec *mobius.PackSpec
			if err := yaml.Unmarshal(s.Spec, &packSpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.Packs = append(specs.Packs, packSpec)

		case mobius.LabelKind:
			var labelSpec *mobius.LabelSpec
			if err := yaml.Unmarshal(s.Spec, &labelSpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.Labels = append(specs.Labels, labelSpec)

		case mobius.PolicyKind:
			var policySpec *mobius.PolicySpec
			if err := yaml.Unmarshal(s.Spec, &policySpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.Policies = append(specs.Policies, policySpec)

		case mobius.AppConfigKind:
			if specs.AppConfig != nil {
				return nil, errors.New("config defined twice in the same file")
			}

			var appConfigSpec interface{}
			if err := yaml.Unmarshal(s.Spec, &appConfigSpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.AppConfig = appConfigSpec

		case mobius.EnrollSecretKind:
			if specs.AppConfig != nil {
				return nil, errors.New("enroll_secret defined twice in the same file")
			}

			var enrollSecretSpec *mobius.EnrollSecretSpec
			if err := yaml.Unmarshal(s.Spec, &enrollSecretSpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.EnrollSecret = enrollSecretSpec

		case mobius.UserRolesKind:
			var userRoleSpec *mobius.UsersRoleSpec
			if err := yaml.Unmarshal(s.Spec, &userRoleSpec); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.UsersRoles = userRoleSpec

		case mobius.TeamKind:
			// unmarshal to a raw map as we don't want to strip away unknown/invalid
			// fields at this point - that validation is done in the apply spec/teams
			// endpoint so that it is enforced for both the API and the CLI.
			rawTeam := make(map[string]json.RawMessage)
			if err := yaml.Unmarshal(s.Spec, &rawTeam); err != nil {
				return nil, fmt.Errorf("unmarshaling %s spec: %w", kind, err)
			}
			specs.Teams = append(specs.Teams, rawTeam["team"])

		default:
			return nil, fmt.Errorf("unknown kind %q", s.Kind)
		}
	}
	return specs, nil
}

// SplitYaml splits a text file into separate yaml documents divided by ---
func SplitYaml(in string) []string {
	var out []string
	for _, chunk := range yamlSeparator.Split(in, -1) {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		out = append(out, chunk)
	}
	return out
}

func generateRandomString(sizeBytes int) string {
	b := make([]byte, sizeBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func ExpandEnv(s string) (string, error) {
	out, err := expandEnv(s, true)
	return out, err
}

// expandEnv expands environment variables for a gitops file.
// $ can be escaped with a backslash, e.g. \$VAR
// \$ can be escaped with another backslash, etc., e.g. \\\$VAR
// $MOBIUS_VAR_XXX will not be expanded. These variables are expanded on the server.
// If secretsMap is not nil, $MOBIUS_SECRET_XXX will be evaluated and put in the map
// If secretsMap is nil, $MOBIUS_SECRET_XXX will cause an error.
func expandEnv(s string, failOnSecret bool) (string, error) {
	// Generate a random escaping prefix that doesn't exist in s.
	var preventEscapingPrefix string
	for {
		preventEscapingPrefix = "PREVENT_ESCAPING_" + generateRandomString(8)
		if !strings.Contains(s, preventEscapingPrefix) {
			break
		}
	}

	s = escapeString(s, preventEscapingPrefix)
	exclusionZones := getExclusionZones(s)

	var err *multierror.Error
	s = mobius.MaybeExpand(s, func(env string, startPos, endPos int) (string, bool) {

		switch {
		case strings.HasPrefix(env, preventEscapingPrefix):
			return "$" + strings.TrimPrefix(env, preventEscapingPrefix), true
		case strings.HasPrefix(env, mobius.ServerVarPrefix):
			// Don't expand mobius vars -- they will be expanded on the server
			return "", false
		case strings.HasPrefix(env, mobius.ServerSecretPrefix):
			if failOnSecret {
				err = multierror.Append(err, fmt.Errorf("environment variables with %q prefix are only allowed in profiles and scripts: %q",
					mobius.ServerSecretPrefix, env))
			}
			return "", false
		}

		// Don't expand mobius vars if they are inside an 'exclusion' zone,
		// i.e. 'description' or 'resolution'....
		for _, z := range exclusionZones {
			if startPos >= z[0] && endPos <= z[1] {
				return "", false
			}
		}

		v, ok := os.LookupEnv(env)
		if !ok {
			err = multierror.Append(err, fmt.Errorf("environment variable %q not set", env))
			return "", false
		}
		return v, true
	})
	if err != nil {
		return "", err
	}
	return s, nil
}

func ExpandEnvBytes(b []byte) ([]byte, error) {
	s, err := ExpandEnv(string(b))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func ExpandEnvBytesIgnoreSecrets(b []byte) ([]byte, error) {
	s, err := expandEnv(string(b), false)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// LookupEnvSecrets only looks up MOBIUS_SECRET_XXX environment variables. Escaping is not supported.
// This is used for finding secrets in scripts only. The original string is not modified.
// A map of secret names to values is updated.
func LookupEnvSecrets(s string, secretsMap map[string]string) error {
	if secretsMap == nil {
		return errors.New("secretsMap cannot be nil")
	}
	var err *multierror.Error
	_ = mobius.MaybeExpand(s, func(env string, startPos, endPos int) (string, bool) {
		if strings.HasPrefix(env, mobius.ServerSecretPrefix) {
			// lookup the secret and save it, but don't replace
			v, ok := os.LookupEnv(env)
			if !ok {
				err = multierror.Append(err, fmt.Errorf("environment variable %q not set", env))
				return "", false
			}
			secretsMap[env] = v
		}
		return "", false
	})
	if err != nil {
		return err
	}
	return nil
}

var escapePattern = regexp.MustCompile(`(\\+\$)`)

func escapeString(s string, preventEscapingPrefix string) string {
	return escapePattern.ReplaceAllStringFunc(s, func(match string) string {
		if len(match)%2 != 0 {
			return match
		}
		return strings.Repeat("\\", (len(match)/2)-1) + "$" + preventEscapingPrefix
	})
}

// getExclusionZones returns which positions inside 's' should be
// excluded from variable interpolation.
func getExclusionZones(s string) [][2]int {
	// We need a different pattern per section because
	// the delimiting end pattern ((?:^\s+\w+:|\z)) includes the next
	// section token, meaning the matching logic won't work in case
	// we have a 'resolution:' followed by a 'description:' or
	// vice versa, and we try using something like (?:resolution:|description:)
	toExclude := []string{
		"resolution",
		"description",
	}
	patterns := make([]*regexp.Regexp, 0, len(toExclude))
	for _, e := range toExclude {
		pattern := fmt.Sprintf(`(?m)^\s*(?:%s:)(.|[\r\n])*?(?:^\s+\w+:|\z)`, e)
		patterns = append(patterns, regexp.MustCompile(pattern))
	}

	var zones [][2]int
	for _, pattern := range patterns {
		result := pattern.FindAllStringIndex(s, -1)
		for _, r := range result {
			zones = append(zones, [2]int{r[0], r[1]})
		}
	}
	return zones
}
