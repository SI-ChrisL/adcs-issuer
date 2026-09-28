package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/djkormo/adcs-issuer/api/v1"
	"github.com/djkormo/adcs-issuer/issuers"
)

const (
	testNamespace   = "default"
	testRequestName = "req-1"
	testIssuerName  = "test-adcs"
	testCredsName   = "test-adcs-creds"
	testClusterNs   = "cert-manager"
)

func selfSignedPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakeADCS serves the three certsrv pages the issuer uses when polling an
// existing request: certnew.cer (the issued cert), certcarc.asp (renewal
// count) and certnew.p7b (the CA chain).
func fakeADCS(t *testing.T, leaf, ca []byte, certHits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/certnew.cer"):
			atomic.AddInt32(certHits, 1)
			w.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = w.Write(leaf)
		case strings.HasSuffix(r.URL.Path, "/certcarc.asp"):
			_, _ = w.Write([]byte("var nRenewals=0;"))
		case strings.HasSuffix(r.URL.Path, "/certnew.p7b"):
			w.Header().Set("Content-Type", "application/x-pkcs7-certificates")
			_, _ = w.Write(ca)
		default:
			http.NotFound(w, r)
		}
	}))
}

// setup returns a reconciler wired to a fake API server holding an approved
// CertificateRequest and a Pending AdcsRequest pointing at srv.
func setup(t *testing.T, srv *httptest.Server) (*AdcsRequestReconciler, client.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, api.AddToScheme(scheme))

	serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	issuerRef := cmmeta.ObjectReference{Group: api.GroupVersion.Group, Kind: "ClusterAdcsIssuer", Name: testIssuerName}

	objs := []client.Object{
		&api.ClusterAdcsIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: testIssuerName},
			Spec: api.ClusterAdcsIssuerSpec{
				URL:            srv.URL,
				CredentialsRef: api.LocalObjectReference{Name: testCredsName},
				CABundle:       serverCA,
			},
		},
		// Empty credentials make the NTLM client fall back to a plain HTTP client.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: testCredsName, Namespace: testClusterNs},
			Data:       map[string][]byte{"username": {}, "password": {}},
		},
		&cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testNamespace},
			Spec:       cmapi.CertificateRequestSpec{IssuerRef: issuerRef, Request: []byte("csr")},
		},
		&api.AdcsRequest{
			ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testNamespace},
			Spec:       api.AdcsRequestSpec{CSRPEM: []byte("csr"), IssuerRef: issuerRef},
			Status:     api.AdcsRequestStatus{State: api.Pending, Id: "42"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&api.AdcsRequest{}, &cmapi.CertificateRequest{}).
		Build()

	recorder := record.NewFakeRecorder(100)
	r := &AdcsRequestReconciler{
		Client:   c,
		Log:      ctrl.Log.WithName("test"),
		Recorder: recorder,
		IssuerFactory: issuers.IssuerFactory{
			Client:                   c,
			ClusterResourceNamespace: testClusterNs,
		},
		CertificateRequestController: &CertificateRequestReconciler{Client: c, Recorder: recorder},
	}
	return r, c
}

func reconcileOnce(t *testing.T, r *AdcsRequestReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testRequestName},
	})
}

func getCR(t *testing.T, c client.Client) *cmapi.CertificateRequest {
	t.Helper()
	cr := &cmapi.CertificateRequest{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRequestName}, cr))
	return cr
}

func readyReason(cr *cmapi.CertificateRequest) string {
	for _, c := range cr.Status.Conditions {
		if c.Type == cmapi.CertificateRequestConditionReady {
			return c.Reason
		}
	}
	return ""
}

// The AdcsRequest status update at the end of the first pass re-enqueues the
// request. That second pass must not overwrite the certificate the first pass
// wrote to the CertificateRequest.
func TestReadyRequestIsNotClobberedOnSecondReconcile(t *testing.T) {
	var certHits int32
	leaf := selfSignedPEM(t, "leaf")
	srv := fakeADCS(t, leaf, selfSignedPEM(t, "ca"), &certHits)
	defer srv.Close()
	r, c := setup(t, srv)

	// Pass 1: ADCS returns the certificate.
	_, err := reconcileOnce(t, r)
	require.NoError(t, err)
	cr := getCR(t, c)
	require.NotEmpty(t, cr.Status.Certificate, "pass 1 should write the certificate")
	assert.Equal(t, cmapi.CertificateRequestReasonIssued, readyReason(cr))
	written := cr.Status.Certificate
	rv := cr.ResourceVersion

	ar := &api.AdcsRequest{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRequestName}, ar))
	require.Equal(t, api.Ready, ar.Status.State)

	// Pass 2: the request is already Ready.
	res, err := reconcileOnce(t, r)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)

	cr = getCR(t, c)
	assert.Equal(t, written, cr.Status.Certificate, "pass 2 must not clobber status.certificate")
	assert.Equal(t, rv, cr.ResourceVersion, "pass 2 must not write the CertificateRequest at all")
	assert.Equal(t, int32(1), atomic.LoadInt32(&certHits), "pass 2 must not contact ADCS")
}

// A 200 application/pkix-cert with an empty body is parsed as Ready by the
// ADCS client. It must never be propagated as Issued with no certificate.
func TestEmptyCertificateIsNotMarkedIssued(t *testing.T) {
	var certHits int32
	srv := fakeADCS(t, nil, selfSignedPEM(t, "ca"), &certHits)
	defer srv.Close()
	r, c := setup(t, srv)

	res, err := reconcileOnce(t, r)
	require.NoError(t, err)
	assert.True(t, res.RequeueAfter > 0, "an empty certificate should be retried")

	cr := getCR(t, c)
	assert.Empty(t, cr.Status.Certificate)
	assert.NotEqual(t, cmapi.CertificateRequestReasonIssued, readyReason(cr), "must not be Issued without a certificate")

	ar := &api.AdcsRequest{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRequestName}, ar))
	assert.Equal(t, api.Pending, ar.Status.State, "AdcsRequest must stay Pending so the poll is retried")
}
