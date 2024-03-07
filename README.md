# Keycloak Pwned Passwords (have i been pwned) Password Policy

This plugin implements a password policy for Keycloak that checks user passwords against
the [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
from [have i been pwned?](https://haveibeenpwned.com).

## Messages

This plugin has only one message key: `invalidPasswordBreached`, which can be changed on the realm's localization
overrides, if on Keycloak >= 24, or by adding / changing the message in
the `src/main/resources/theme-resources/messages` localization files, if on Keycloak < 24, and recompiling the plugin.
