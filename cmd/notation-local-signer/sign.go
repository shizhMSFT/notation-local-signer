package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/spf13/cobra"
)

func signCommand() *cobra.Command {
	return &cobra.Command{
		Use:  string(proto.CommandGenerateSignature),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign()
		},
	}
}

func runSign() error {
	// decode request
	var req proto.GenerateSignatureRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}

	// sign
	resp, err := sign(&req)
	if err != nil {
		return err
	}

	// encode response
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func sign(req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	// read certificate
	certs, err := x509.ReadCertificateFile(req.KeyID)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to read certificate file: %w", err),
		}
	}
	if len(certs) == 0 {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("no certificate found"),
		}
	}

	// read private key from environment variable
	env := req.PluginConfig["env"]
	if env == "" {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("no private key specified"),
		}
	}
	data, err := base64.StdEncoding.DecodeString(os.Getenv(env))
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to decode private key from environment variable %q: %w", env, err),
		}
	}
	key, err := x509.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to parse private key from environment variable %q: %w", env, err),
		}
	}

	// sign
	signer, err := signature.NewLocalSigner(certs, key)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to create signer: %w", err),
		}
	}
	sig, certs, err := signer.Sign(req.Payload)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to sign payload: %w", err),
		}
	}

	// generate response
	keySpec, err := signer.KeySpec()
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to get key spec: %w", err),
		}
	}
	signingAlgorithm, err := proto.EncodeSigningAlgorithm(keySpec.SignatureAlgorithm())
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to encode signing algorithm: %w", err),
		}
	}
	certChain := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		certChain = append(certChain, cert.Raw)
	}
	return &proto.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        sig,
		SigningAlgorithm: string(signingAlgorithm),
		CertificateChain: certChain,
	}, nil
}
