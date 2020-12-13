package set

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/api"
	"github.com/cli/cli/internal/ghrepo"
	"github.com/cli/cli/pkg/cmd/secret/shared"
	"github.com/cli/cli/pkg/cmdutil"
	"github.com/cli/cli/pkg/iostreams"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/box"
)

type SetOptions struct {
	HttpClient func() (*http.Client, error)
	IO         *iostreams.IOStreams
	BaseRepo   func() (ghrepo.Interface, error)

	RandomOverride io.Reader

	SecretName      string
	OrgName         string
	Body            string
	Visibility      string
	RepositoryNames []string

	Wizard bool
}

func NewCmdSet(f *cmdutil.Factory, runF func(*SetOptions) error) *cobra.Command {
	opts := &SetOptions{
		IO:         f.IOStreams,
		HttpClient: f.HttpClient,
	}

	cmd := &cobra.Command{
		Use:   "set <secret-name>",
		Short: "Create or update secrets",
		Long:  "Locally encrypt a new or updated secret at either the repository or organization level and send it to GitHub for storage.",
		Example: heredoc.Doc(`
			$ cat SECRET.txt | gh secret set NEW_SECRET
			$ gh secret set NEW_SECRET -b"some literal value"
			$ gh secret set NEW_SECRET -b"@file.json"
			$ gh secret set ORG_SECRET --org
			$ gh secret set ORG_SECRET --org=anotherOrg --visibility=selected -r="repo1,repo2,repo3"
			$ gh secret set ORG_SECRET --org=anotherOrg --visibility="all"
`),
		Args: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("visibility") && !cmd.Flags().Changed("org") && !cmd.Flags().Changed("body") {
				opts.Wizard = true
				return nil
			}

			if len(args) != 1 {
				return &cmdutil.FlagError{Err: errors.New("must pass single secret name")}
			}
			if !cmd.Flags().Changed("body") && opts.IO.IsStdinTTY() {
				return &cmdutil.FlagError{Err: errors.New("no --body specified but nothing on STIDN")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// support `-R, --repo` override
			opts.BaseRepo = f.BaseRepo

			if !opts.Wizard {
				opts.SecretName = args[0]

<<<<<<< HEAD
			err := validSecretName(opts.SecretName)
			if err != nil {
				return err
			}

			if cmd.Flags().Changed("visibility") {
				if opts.OrgName == "" {
					return &cmdutil.FlagError{Err: errors.New(
						"--visibility not supported for repository secrets; did you mean to pass --org?")}
				}

				if opts.Visibility != shared.All && opts.Visibility != shared.Private && opts.Visibility != shared.Selected {
=======
				if cmd.Flags().Changed("visibility") {
					if opts.OrgName == "" {
						return &cmdutil.FlagError{Err: errors.New(
							"--visibility not supported for repository secrets; did you mean to pass --org?")}
					}

					if opts.Visibility != shared.VisAll && opts.Visibility != shared.VisPrivate && opts.Visibility != shared.VisSelected {
						return &cmdutil.FlagError{Err: errors.New(
							"--visibility must be one of `all`, `private`, or `selected`")}
					}
				}

				if cmd.Flags().Changed("repos") && opts.Visibility != shared.VisSelected {
>>>>>>> 441-secrets-survey
					return &cmdutil.FlagError{Err: errors.New(
						"--repos only supported when --visibility='selected'")}
				}

<<<<<<< HEAD
				if opts.Visibility != shared.Selected && cmd.Flags().Changed("repos") {
					return &cmdutil.FlagError{Err: errors.New(
						"--repos only supported when --visibility='selected'")}
				}

				if opts.Visibility == shared.Selected && !cmd.Flags().Changed("repos") {
					return &cmdutil.FlagError{Err: errors.New(
						"--repos flag required when --visibility='selected'")}
				}
			} else {
				if cmd.Flags().Changed("repos") {
					opts.Visibility = shared.Selected
				}
=======
				if opts.Visibility == shared.VisSelected && len(opts.RepositoryNames) == 0 {
					return &cmdutil.FlagError{Err: errors.New(
						"--repos flag required when --visibility='selected'")}
				}
>>>>>>> 441-secrets-survey
			}

			if runF != nil {
				return runF(opts)
			}

			return setRun(opts)
		},
	}
	cmd.Flags().StringVarP(&opts.OrgName, "org", "o", "", "List secrets for an organization")
	cmd.Flags().StringVarP(&opts.Visibility, "visibility", "v", "private", "Set visibility for an organization secret: `all`, `private`, or `selected`")
	cmd.Flags().StringSliceVarP(&opts.RepositoryNames, "repos", "r", []string{}, "List of repository names for `selected` visibility")
	cmd.Flags().StringVarP(&opts.Body, "body", "b", "-", "Provide either a literal string or a file path; prepend file paths with an @. Reads from STDIN if not provided.")

	return cmd
}

func setRun(opts *SetOptions) error {
	c, err := opts.HttpClient()
	if err != nil {
		return fmt.Errorf("could not create http client: %w", err)
	}
	client := api.NewClientFromHTTP(c)

<<<<<<< HEAD
	orgName := opts.OrgName
=======
	if opts.Wizard {
		return setWizard(client, opts)
	}

	body, err := getBody(opts)
	if err != nil {
		return fmt.Errorf("did not understand secret body: %w", err)
	}
>>>>>>> 441-secrets-survey

	var baseRepo ghrepo.Interface
	if orgName == "" {
		baseRepo, err = opts.BaseRepo()
		if err != nil {
			return fmt.Errorf("could not determine base repo: %w", err)
		}
	}

<<<<<<< HEAD
	var pk *PubKey
	if orgName != "" {
		pk, err = getOrgPublicKey(client, orgName)
=======
	host := ghinstance.OverridableDefault()
	if opts.OrgName == "@owner" {
		opts.OrgName = baseRepo.RepoOwner()
		host = baseRepo.RepoHost()
	}

	pk, err := getPubKey(client, baseRepo, host, *opts)
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	encoded, err := encrypt(body, *pk, *opts)
	if err != nil {
		return fmt.Errorf("failed to encrypt body: %w", err)
	}

	if opts.OrgName != "" {
		var orgRepos []api.OrgRepo
		if opts.Visibility == shared.VisSelected {
			orgRepos, err = mapRepoNamesToID(client, host, opts.OrgName, opts.RepositoryNames)
			if err != nil {
				return fmt.Errorf("failed to get IDs for repo names: %w", err)
			}
		}

		err = putOrgSecret(client, pk, host, encoded, orgRepos, *opts)
>>>>>>> 441-secrets-survey
	} else {
		err = putRepoSecret(client, pk, baseRepo, encoded, *opts)
	}
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	return nil
}

// TODO validate secret name: only letters and _
// TODO notice update case for orgs, pre-check org visibility list

func setWizard(client *api.Client, opts *SetOptions) error {
	var err error

	baseRepo, err := opts.BaseRepo()
	if err != nil {
		return fmt.Errorf("could not determine base repo: %w", err)
	}

	secretType, err := promptSecretType()
	if err != nil {
		return fmt.Errorf("failed to get secret type: %w", err)
	}

	var visibility string
	var orgRepos []api.OrgRepo
	var orgName string
	hostname := ghinstance.OverridableDefault()
	if secretType == orgType {
		orgName, err = promptOrgName(baseRepo.RepoOwner())
		if err != nil {
			return fmt.Errorf("failed to get organization name: %w", err)
		}

		if orgName == baseRepo.RepoOwner() {
			hostname = baseRepo.RepoHost()
		}

		visibility, err = promptVisibility()
		if err != nil {
			return fmt.Errorf("failed to get visibility: %w", err)
		}

		if visibility == shared.VisSelected {
			orgRepos, err = promptRepositories(client, hostname, orgName)
			if err != nil {
				return fmt.Errorf("failed to get repository names: %w", err)
			}
		}
	}

	secretName, err := promptSecretName()
	if err != nil {
		return fmt.Errorf("failed to get secret name: %w", err)
	}

	secretBody, err := promptSecretBody()
	if err != nil {
		return fmt.Errorf("failed to get secret body", err)
	}

	opts.OrgName = orgName
	opts.SecretName = secretName
	opts.Visibility = visibility

	pk, err := getPubKey(client, baseRepo, hostname, *opts)
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	encoded, err := encrypt(secretBody, *pk, *opts)
	if err != nil {
		return fmt.Errorf("failed to encrypt body: %w", err)
	}

<<<<<<< HEAD
	encoded := base64.StdEncoding.EncodeToString(eBody)

	if orgName != "" {
		err = putOrgSecret(client, pk, *opts, encoded)
=======
	if orgName != "" {
		err = putOrgSecret(client, pk, hostname, encoded, orgRepos, *opts)
>>>>>>> 441-secrets-survey
	} else {
		err = putRepoSecret(client, pk, baseRepo, encoded, *opts)
	}
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	if opts.IO.IsStdoutTTY() {
		cs := opts.IO.ColorScheme()

		if orgName == "" {
			fmt.Fprintf(opts.IO.Out, "%s Set secret %s for %s\n", cs.SuccessIcon(), opts.SecretName, ghrepo.FullName(baseRepo))
		} else {
			fmt.Fprintf(opts.IO.Out, "%s Set secret %s for %s\n", cs.SuccessIcon(), opts.SecretName, orgName)
		}
	}

	return nil
}

func validSecretName(name string) error {
	if name == "" {
		return errors.New("secret name cannot be blank")
	}

	if strings.HasPrefix(name, "GITHUB_") {
		return errors.New("secret name cannot begin with GITHUB_")
	}

	leadingNumber := regexp.MustCompile(`^[0-9]`)
	if leadingNumber.MatchString(name) {
		return errors.New("secret name cannot start with a number")
	}

	validChars := regexp.MustCompile(`^([0-9]|[a-z]|[A-Z]|_)+$`)
	if !validChars.MatchString(name) {
		return errors.New("secret name can only contain letters, numbers, and _")
	}

	return nil
}

func getBody(opts *SetOptions) (body []byte, err error) {
	if opts.Body == "-" {
		body, err = ioutil.ReadAll(opts.IO.In)
		if err != nil {
			return nil, fmt.Errorf("failed to read from STDIN: %w", err)
		}

		return
	}

	if strings.HasPrefix(opts.Body, "@") {
		body, err = opts.IO.ReadUserFile(opts.Body[1:])
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", opts.Body[1:], err)
		}

		return
	}

	return []byte(opts.Body), nil
}

func getPubKey(client *api.Client, baseRepo ghrepo.Interface, host string, opts SetOptions) (pk *PubKey, err error) {
	if opts.OrgName != "" {
		pk, err = getOrgPublicKey(client, host, opts.OrgName)
	} else {
		pk, err = getRepoPubKey(client, baseRepo)
	}

	return
}

func encrypt(body []byte, pk PubKey, opts SetOptions) (string, error) {
	eBody, err := box.SealAnonymous(nil, body, &pk.Raw, opts.RandomOverride)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(eBody), nil
}

func setSecret(client *api.Client, pk PubKey, host, encoded string, baseRepo ghrepo.Interface, opts SetOptions) error {
	// TODO
	return nil
}
