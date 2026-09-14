/**
 * Application Configuration Constants
 *
 * This file used to carry twelve blocks; eleven had no importer anywhere in
 * the repo, and three of their values had drifted away from the server
 * (session timeout 30 min vs the backend's 480, audit retention ceiling 365
 * vs the backend's 3650, backup upload cap 100 MB vs the server's hard 50 MB).
 * Being dead, none of them was a bug — but "adopting" the file, as was once
 * suggested, would have turned all three into one. They are gone rather than
 * corrected, so nothing here can be adopted on trust again.
 *
 * Whatever is added back belongs to a live call site, checked against the
 * backend default it mirrors.
 */

// Certificate & Key Validity
// Mirrors backend/utils/validity.py. TEMPLATE_DEFAULT_DAYS and DEFAULT_DAYS
// answer different questions and are allowed to differ: a template defaults
// to the CA/Browser Forum ceiling for public TLS, a one-off certificate to a
// year. What is not allowed is a third copy of either number, which is how
// the template screen came to display 365 for a column the server defaults
// to 397.
export const VALIDITY = {
  // Read by CSRsPage as the initial validity of a CSR signature request.
  // Matches the 365 hardcoded in IssueCertificateForm and OperationsPage.
  DEFAULT_DAYS: 365,
  MAX_DAYS: 3650,
  TEMPLATE_DEFAULT_DAYS: 397,
}
