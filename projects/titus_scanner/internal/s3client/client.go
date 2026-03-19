package s3client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Options holds configuration for connecting to S3-compatible storage.
type Options struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
}

// Client wraps an S3-compatible client with the configured bucket name.
type Client struct {
	client *minio.Client
	bucket string
}

// New creates a new S3 client wrapper. The endpoint may include an http(s) scheme;
// if so, the scheme is parsed to determine whether to use SSL.
func New(opts Options) (*Client, error) {
	endpoint := opts.Endpoint
	useSSL := false

	// Parse the endpoint to extract host and determine SSL
	if strings.HasPrefix(endpoint, "https://") {
		useSSL = true
		endpoint = strings.TrimPrefix(endpoint, "https://")
	} else if strings.HasPrefix(endpoint, "http://") {
		useSSL = false
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else {
		// Try to parse as a URL in case it has a scheme
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			endpoint = u.Host
			useSSL = u.Scheme == "https"
		}
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opts.AccessKey, opts.SecretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}

	return &Client{
		client: client,
		bucket: opts.Bucket,
	}, nil
}

// Download retrieves the object identified by objectID from S3 storage and writes it
// to a temporary file. It first checks the object size against maxSizeBytes.
// Returns the path to the temporary file, the object size in bytes, and any error.
// The caller is responsible for removing the temporary file when done.
func (c *Client) Download(ctx context.Context, objectID string, maxSizeBytes int64) (string, int64, error) {
	// Get object metadata to check size
	info, err := c.client.StatObject(ctx, c.bucket, objectID, minio.StatObjectOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("failed to stat object %s: %w", objectID, err)
	}

	objectSize := info.Size
	slog.Debug("Object metadata retrieved",
		"object_id", objectID,
		"size_bytes", objectSize,
		"size_mb", objectSize/(1024*1024),
	)

	if maxSizeBytes > 0 && objectSize > maxSizeBytes {
		return "", objectSize, fmt.Errorf(
			"object %s size %d bytes (%d MB) exceeds limit %d bytes (%d MB)",
			objectID, objectSize, objectSize/(1024*1024),
			maxSizeBytes, maxSizeBytes/(1024*1024),
		)
	}

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "titus-download-*")
	if err != nil {
		return "", objectSize, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Download the object
	obj, err := c.client.GetObject(ctx, c.bucket, objectID, minio.GetObjectOptions{})
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", objectSize, fmt.Errorf("failed to get object %s: %w", objectID, err)
	}
	defer obj.Close()

	written, err := io.Copy(tmpFile, obj)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", objectSize, fmt.Errorf("failed to write object %s to temp file: %w", objectID, err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", objectSize, fmt.Errorf("failed to close temp file: %w", err)
	}

	slog.Debug("Downloaded object to temp file",
		"object_id", objectID,
		"bytes_written", written,
		"temp_path", tmpPath,
	)

	return tmpPath, objectSize, nil
}
