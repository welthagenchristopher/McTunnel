### V1.00:

**Known issues:**

1. System warning on RSA key generation + auto sign policy.
2. Lack of key based authentication support.
3. Lack of automatic & self tests resulting in a lack of
   knowledge on how this script behaves handling several
   connections (10+).
4. Lack of persistent memory after closing.

**Planned fixes:**

1. Time based, and manual key regeneration using system time.
2. Add public key authentication for improved security.
3. Implement self tests on initial hosting, and connection,
   possibly via a dummy TCP server to test port mapping.
4. Implement config file to save mappings to + load saved
   profile button to bring them up.
   
