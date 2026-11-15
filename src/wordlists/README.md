# Vendored wordlists

## `eff_large_wordlist.txt`

* **What:** the EFF Long Wordlist for dice-generated passphrases: 7776 words, each a line `<five dice digits>\t<word>`.
* **Source:** https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt, retrieved 2026-11-16, byte-exact.
* **Announcement:** https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
* **SHA-256:** `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`. Pinned in `src/passphrase.rs`: checked at run time before the first passphrase (generation fails closed on a mismatch) and by the tests. It is not a compile-time check.
* **Cross-check:** identical word-for-word and index-for-index to `diceware/wordlists/wordlist_en_eff.txt` in the PyPI `diceware` 1.0.1 sdist. That is an independent copy, compared on 2026-11-16.
* **Checked properties:**
  * 7776 unique words, and the dice indices 11111–66666 are complete and in order.
  * Words are lowercase `a–z`, 3–9 characters long; four contain a hyphen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`), so Keymesh separates words only with a space or a period.
  * No word is a prefix of another.
* **Licence:** under EFF's site-wide copyright policy (https://www.eff.org/copyright), its content, wordlists included, is published under the Creative Commons Attribution 3.0 US licence (CC BY 3.0 US, https://creativecommons.org/licenses/by/3.0/us/). Attribution: "EFF Long Wordlist, Electronic Frontier Foundation".
