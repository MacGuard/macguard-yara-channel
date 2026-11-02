/* Portal guide: static text, ES in the HTML, EN here. Elements that contain links keep the Spanish markup in Spanish and get plain English text. */
(function(){
var D={es:{},en:{h:'Portal guide: download, verify and use the data',intro:'How to download the packages, check their hashes and signatures, keep them up to date, which engines and formats are compatible, which licences apply and how to query the data. The full technical documentation is under Documentation.',
 d_h:'1. Download',d_p:'Every family has its own packages under Downloads. YARA Community is free and public. Intelligence packages appear only if they were verified in the same publication; a family without a verified package is shown as NOT AVAILABLE, with no download button.',
 d_p2:'Always download the package (.tar.gz), its manifest.json and its manifest.sigstore.json of the same version.',
 h_h:'2. Verify the hashes',h_p:'Compare the package SHA-256 with the one on the Downloads page, and each file with its entry in manifest.json:',h_p2:'A download verification hash is not a malware indicator: they are different things.',
 s_h:'3. Verify the signature',s_p:'The YARA Community manifest is signed with Sigstore (no keys to keep). Require the identity of the publish.yml workflow of this repository on main and the GitHub Actions issuer:',
 s_p2:'Intelligence packages use the same scheme: a signed manifest with its Sigstore bundle. Check that the certificate identity is this repository’s publishing workflow on main; if it does not match, discard the package. For transparency and inclusion proofs see Transparency and the verify_public_release.py verifier.',
 u_h:'4. Update',u_p:'latest.json gives the latest published YARA Community version and packages.json the list of verified packages. Update only after verifying the signature and hashes of the new version; if verification fails, keep the previous version.',
 c_h:'5. Compatibility',c1:'YARA Community: rules validated with the pipeline’s YARA compiler; "validated" means the compiler accepted them, not that they detect anything in particular.',c2:'YARA-X is an engine: its compatibility is measured, it is not a third rule collection.',
 c3:'Vulnerability data: normalised JSON (schema macguard.intel-kev/1 for CISA KEV), not rules for any engine.',c4:'Sigma, Suricata and ClamAV: no package is published yet; no list of names is presented as a working package.',
 l_h:'6. Licences and attribution',l_p:'Every rule file keeps its source and licence in the manifest. Intelligence sources are used only once approved; their state is in sources.json.',
 l_kev:'CISA KEV: public domain (CC0 1.0). Source: CISA Known Exploited Vulnerabilities Catalog. MacGuard is not affiliated with or endorsed by CISA.',
 a_h:'7. Query the data (API)',a_p:'The lookup service (contract macguard.intel-search/1) is not published yet. When it is, it will offer: GET /v1/vulns/search (paged, with filters), GET /v1/vulns/{id} (contract macguard.intel-vulnerability/1) and GET /v1/vulns/sources. PREMIUM sections are authorised on the server.',
 a_p2:'Meanwhile the verified CISA KEV catalogue is published as static files: kev/index.json and one file per year with its SHA-256 in the index.'}};
MG.i18n(D,function(){});
})();
