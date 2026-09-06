//! Hostname suffixes that name a third-party service, and what it means when a
//! record points at one.
//!
//! This is the table behind the subdomain-takeover check. A CNAME whose target
//! ends in one of these suffixes is pointing at a resource on somebody else's
//! platform, and if that resource was deprovisioned the name may be claimable
//! by whoever asks for it next — at which point they serve content on your
//! domain, with a valid certificate.
//!
//! The table deliberately records *how* claimable, because the three cases lead
//! to different work:
//!
//! - [`Claim::Open`] — the platform hands out names first-come. An unclaimed
//!   name is takeable by anyone today. This is the finding.
//! - [`Claim::Verified`] — the platform requires proof of domain ownership
//!   before serving a custom hostname. A dangling record is still a dead
//!   reference and still worth removing, but it is not an open door.
//! - [`Claim::Own`] — the resource is in the reader's own Cloudflare account.
//!   Nobody else can claim it; what it says instead is that a bucket, a Worker
//!   or a Pages project is published under this name.
//!
//! Only the API half of the check lives here. Whether the resource behind the
//! name still exists cannot be answered by reading configuration, and settling
//! it needs a resolution against the outside world — an active step.

/// How takeable an unclaimed name on a platform is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// First-come naming: anyone can register the name and serve on it.
    Open,
    /// The platform verifies domain ownership before serving.
    Verified,
    /// A Cloudflare resource, so it is in the reader's own account.
    Own,
}

/// A platform, identified by the suffix its hostnames carry.
#[derive(Debug, Clone, Copy)]
pub struct Provider {
    pub suffix: &'static str,
    pub name: &'static str,
    pub claim: Claim,
}

/// The suffix table, longest-match-wins at lookup.
///
/// Kept to platforms whose naming behaviour is well established. A suffix that
/// is only sometimes claimable belongs under [`Claim::Verified`] rather than
/// being left out, because a dangling reference is worth reporting either way.
const PROVIDERS: &[Provider] = &[
    // Object storage and CDNs: bucket and distribution names are global and
    // first-come on most of these.
    p("s3.amazonaws.com", "Amazon S3", Claim::Open),
    p("s3-website.amazonaws.com", "Amazon S3 website", Claim::Open),
    p("elasticbeanstalk.com", "AWS Elastic Beanstalk", Claim::Open),
    p("cloudfront.net", "Amazon CloudFront", Claim::Verified),
    p(
        "storage.googleapis.com",
        "Google Cloud Storage",
        Claim::Open,
    ),
    p("appspot.com", "Google App Engine", Claim::Open),
    p("firebaseapp.com", "Firebase Hosting", Claim::Open),
    p("web.app", "Firebase Hosting", Claim::Open),
    p("blob.core.windows.net", "Azure Blob Storage", Claim::Open),
    p("azurewebsites.net", "Azure App Service", Claim::Open),
    p("cloudapp.net", "Azure Cloud Services", Claim::Open),
    p("cloudapp.azure.com", "Azure Cloud Services", Claim::Open),
    p("trafficmanager.net", "Azure Traffic Manager", Claim::Open),
    p("azureedge.net", "Azure CDN", Claim::Open),
    p("azure-api.net", "Azure API Management", Claim::Open),
    // Application platforms.
    p("herokuapp.com", "Heroku", Claim::Open),
    p("herokudns.com", "Heroku", Claim::Open),
    p("netlify.app", "Netlify", Claim::Verified),
    p("netlify.com", "Netlify", Claim::Verified),
    p("vercel.app", "Vercel", Claim::Verified),
    p("now.sh", "Vercel (legacy)", Claim::Verified),
    p("surge.sh", "Surge", Claim::Open),
    p("pantheonsite.io", "Pantheon", Claim::Open),
    p("wpengine.com", "WP Engine", Claim::Verified),
    p("acquia-sites.com", "Acquia", Claim::Verified),
    p("fastly.net", "Fastly", Claim::Verified),
    // Documentation, blogs and site builders.
    p("github.io", "GitHub Pages", Claim::Open),
    p("gitlab.io", "GitLab Pages", Claim::Open),
    p("bitbucket.io", "Bitbucket Pages", Claim::Open),
    p("readthedocs.io", "Read the Docs", Claim::Open),
    p("readme.io", "ReadMe", Claim::Open),
    p("ghost.io", "Ghost", Claim::Open),
    p("wordpress.com", "WordPress.com", Claim::Verified),
    p("tumblr.com", "Tumblr", Claim::Open),
    p("webflow.io", "Webflow", Claim::Open),
    p("wixdns.net", "Wix", Claim::Verified),
    p("bigcartel.com", "Big Cartel", Claim::Open),
    p("cargocollective.com", "Cargo", Claim::Open),
    p("hatenablog.com", "Hatena Blog", Claim::Open),
    p("strikinglydns.com", "Strikingly", Claim::Open),
    p("launchrock.com", "LaunchRock", Claim::Open),
    p("unbouncepages.com", "Unbounce", Claim::Open),
    p("instapage.com", "Instapage", Claim::Open),
    p("simplebooklet.com", "Simplebooklet", Claim::Open),
    // Commerce.
    p("myshopify.com", "Shopify", Claim::Verified),
    p("tictail.com", "Tictail", Claim::Open),
    // Support, status and marketing tools — the classic sources, because they
    // are set up by a team that later stops using them.
    p("zendesk.com", "Zendesk", Claim::Open),
    p("freshdesk.com", "Freshdesk", Claim::Open),
    p("desk.com", "Desk.com", Claim::Open),
    p("uservoice.com", "UserVoice", Claim::Open),
    p("helpscoutdocs.com", "Help Scout", Claim::Open),
    p("statuspage.io", "Statuspage", Claim::Verified),
    p("hostedstatus.com", "StatusCast", Claim::Open),
    p("canny.io", "Canny", Claim::Open),
    p("intercom.help", "Intercom", Claim::Open),
    p("custom.intercom.help", "Intercom", Claim::Open),
    p("hs-sites.com", "HubSpot", Claim::Verified),
    p("hubspot.net", "HubSpot", Claim::Verified),
    p("createsend.com", "Campaign Monitor", Claim::Open),
    p("campaignmonitor.com", "Campaign Monitor", Claim::Open),
    p("getresponse.com", "GetResponse", Claim::Open),
    p("agilecrm.com", "Agile CRM", Claim::Open),
    p("aftership.com", "AfterShip", Claim::Open),
    p("smartling.com", "Smartling", Claim::Open),
    p("frontify.com", "Frontify", Claim::Open),
    p("teamwork.com", "Teamwork", Claim::Open),
    p("short.io", "Short.io", Claim::Open),
    p("brightcove.com", "Brightcove", Claim::Open),
    // Cloudflare's own. Not takeable by anyone else — these say that something
    // in this account is published under the name.
    p("r2.dev", "Cloudflare R2 public bucket", Claim::Own),
    p("pages.dev", "Cloudflare Pages", Claim::Own),
    p("workers.dev", "Cloudflare Workers", Claim::Own),
];

const fn p(suffix: &'static str, name: &'static str, claim: Claim) -> Provider {
    Provider {
        suffix,
        name,
        claim,
    }
}

/// The platform a hostname belongs to, if it is a known one.
///
/// Matches on a label boundary so `notevil.github.io.example.com` — a hostname
/// inside a zone you control that merely contains a suffix — is not mistaken
/// for a GitHub Pages target. The longest matching suffix wins, so
/// `custom.intercom.help` beats `intercom.help`.
pub fn lookup(host: &str) -> Option<&'static Provider> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    PROVIDERS
        .iter()
        .filter(|p| {
            host == p.suffix
                || host
                    .strip_suffix(p.suffix)
                    .is_some_and(|head| head.ends_with('.'))
        })
        .max_by_key(|p| p.suffix.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_on_a_known_platform_is_recognized() {
        let p = lookup("my-app.herokuapp.com").unwrap();
        assert_eq!(p.name, "Heroku");
        assert_eq!(p.claim, Claim::Open);
    }

    #[test]
    fn the_match_is_on_a_label_boundary_not_a_substring() {
        // A host inside a zone you control that merely ends with the letters of
        // a suffix is not a target on that platform.
        assert!(lookup("evilgithub.io").is_none());
        assert!(lookup("notherokuapp.com").is_none());
        assert!(lookup("github.io.example.com").is_none());
        assert!(lookup("pages.example.com").is_none());
    }

    #[test]
    fn the_bare_suffix_is_itself_a_match() {
        // A CNAME straight at `github.io` is as dangling as one at a name under
        // it, and drops out of a boundary-only rule.
        assert!(lookup("github.io").is_some());
    }

    #[test]
    fn the_longest_suffix_wins() {
        // Both entries match; the specific one is the one to report.
        assert_eq!(
            lookup("docs.custom.intercom.help").unwrap().suffix,
            "custom.intercom.help"
        );
        assert_eq!(
            lookup("docs.intercom.help").unwrap().suffix,
            "intercom.help"
        );
    }

    #[test]
    fn matching_ignores_case_and_a_trailing_root_dot() {
        assert!(lookup("My-App.HerokuApp.Com.").is_some());
    }

    #[test]
    fn cloudflares_own_platforms_are_marked_as_the_readers_own() {
        // Nobody else can claim these, so they are an inventory fact rather
        // than an open door.
        assert_eq!(lookup("pub-abc123.r2.dev").unwrap().claim, Claim::Own);
        assert_eq!(lookup("site.pages.dev").unwrap().claim, Claim::Own);
    }

    #[test]
    fn an_ordinary_hostname_matches_nothing() {
        assert!(lookup("origin.example.com").is_none());
        assert!(lookup("").is_none());
    }
}
