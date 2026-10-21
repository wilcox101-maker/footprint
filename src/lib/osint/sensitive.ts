import type { Entity } from "@/lib/osint/types";

const HIDDEN_RELATIONS = new Set(["published-phone", "published-address", "geolocation"]);

/** Hide published contact details unless the operator turned the setting on. */
export function displayEntity(entity: Entity, showDetails: boolean): { title: string; value: string; lines: string[]; photo?: string } {
  const photo = /^https:\/\//i.test(entity.meta.photo ?? "") ? entity.meta.photo : undefined;
  if (showDetails) {
    const lines = Object.entries(entity.meta)
      .filter(([key, value]) => value && !["role", "linkTo", "linkRel", "missingFrom", "missingModule", "photo"].includes(key))
      .slice(0, 8)
      .map(([key, value]) => `${key}: ${value}`);
    return { title: entity.title, value: entity.value, lines, photo };
  }
  if (HIDDEN_RELATIONS.has(entity.relation)) {
    const label =
      entity.relation === "published-phone" ? "Published phone" : entity.relation === "published-address" ? "Published address" : "Approximate location";
    return { title: label, value: "Hidden", lines: ["Turn on public details in Settings to read this."] };
  }
  return {
    title: maskText(entity.title),
    value: maskText(entity.value),
    lines: [
      ...(photo ? ["Photo hidden"] : []),
      ...(entity.meta.classes ? ["Breach categories hidden"] : []),
      ...(entity.meta.phone || entity.meta.address ? ["Published contact hidden"] : []),
    ],
  };
}

export function maskText(value: string): string {
  return value
    .replace(/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{0,63}@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g, "$1•••@$2")
    .replace(/\+\d[\d\s().-]{6,}\d/g, "phone hidden");
}

export type RemovalLink = {
  group: string;
  title: string;
  detail: string;
  href: string;
  /** Published privacy mailbox. Present only when the broker's own site lists it. */
  mail?: string;
  /** Listing URL must be on one of these hosts before a mail request is opened. */
  hosts?: string[];
};

/** Official takedown and opt-out pages. These remove a listing from that site or from search, not from this browser. */
export const TAKEDOWN_LINKS: RemovalLink[] = [
  {
    group: "Search engines",
    title: "Google Results about you",
    detail: "Ask Google to drop a result that shows your address, phone, email, or a government ID number. This does not delete the page that published it.",
    href: "https://myactivity.google.com/results-about-you",
  },
  {
    group: "Data brokers",
    title: "California DROP",
    detail: "California residents can send one deletion request to registered data brokers. Brokers must process it. It does not cover every people-search site.",
    href: "https://privacy.ca.gov/DROP",
  },
  {
    group: "Data brokers",
    title: "Spokeo opt-out",
    detail: "Search your name, copy the listing URL, paste it on the opt-out form, and confirm the email. Also covers some Spokeo-run directories, not every sister site.",
    href: "https://www.spokeo.com/optout",
    mail: "privacy@spokeo.com",
    hosts: ["spokeo.com"],
  },
  {
    group: "Data brokers",
    title: "PeopleConnect suppression",
    detail: "One request covers Intelius, TruthFinder, Instant Checkmate, and US Search. Recheck each site. Classmates is not always included.",
    href: "https://suppression.peopleconnect.us",
  },
  {
    group: "Data brokers",
    title: "BeenVerified opt-out",
    detail: "Submit the listing, then use the confirmation link. PeopleLooker and PeopleSmart are related but often need their own form.",
    href: "https://www.beenverified.com/app/optout/search",
    mail: "privacy@beenverified.com",
    hosts: ["beenverified.com"],
  },
  {
    group: "Data brokers",
    title: "Whitepages suppression",
    detail: "Paste the listing URL. The faster path asks for a phone verification. 411.com uses the same company.",
    href: "https://www.whitepages.com/suppression-requests",
    mail: "privacyrequest@whitepages.com",
    hosts: ["whitepages.com", "411.com"],
  },
  {
    group: "Data brokers",
    title: "TruePeopleSearch removal",
    detail: "Use the site’s removal form and answer the confirmation email. The link expires quickly.",
    href: "https://www.truepeoplesearch.com/removal",
  },
  {
    group: "Data brokers",
    title: "FastPeopleSearch removal",
    detail: "Same operator family as several other free people-search sites. Opt out here, then check the sister sites separately.",
    href: "https://www.fastpeoplesearch.com/removal",
  },
  {
    group: "Data brokers",
    title: "LexisNexis consumer opt-out",
    detail: "Public-record and identity products. The form may ask you to prove it is your record. It does not show or return a Social Security number.",
    href: "https://consumer.risk.lexisnexis.com/opt",
  },
  {
    group: "Phones, mail, and credit",
    title: "National Do Not Call Registry",
    detail: "Register a published phone number. This stops many sales calls. It does not delete a people-search listing.",
    href: "https://www.donotcall.gov/",
  },
  {
    group: "Phones, mail, and credit",
    title: "Opt out of prescreened offers",
    detail: "Official opt-out for firm offers of credit and insurance.",
    href: "https://www.optoutprescreen.com/",
  },
  {
    group: "Phones, mail, and credit",
    title: "Annual credit report",
    detail: "See whether a new account was opened. This is the official free report, not a Social Security number search.",
    href: "https://www.annualcreditreport.com/",
  },
  {
    group: "Phones, mail, and credit",
    title: "Equifax security freeze",
    detail: "Free freeze. Place one at each bureau, not only here.",
    href: "https://www.equifax.com/personal/credit-report-services/credit-freeze/",
  },
  {
    group: "Phones, mail, and credit",
    title: "Experian security freeze",
    detail: "Free freeze.",
    href: "https://www.experian.com/help/credit-freeze/",
  },
  {
    group: "Phones, mail, and credit",
    title: "TransUnion security freeze",
    detail: "Free freeze.",
    href: "https://www.transunion.com/credit-freeze",
  },
  {
    group: "Phones, mail, and credit",
    title: "IdentityTheft.gov",
    detail: "Federal recovery plan if a government identifier is already being misused.",
    href: "https://www.identitytheft.gov/",
  },
  {
    group: "Phones, mail, and credit",
    title: "Have I Been Pwned",
    detail: "Check an email address. A breach can name the category “Social security numbers.” The number itself is not returned.",
    href: "https://haveibeenpwned.com/",
  },
];

export const TAKEDOWN_METHOD = [
  "Search your own name on the broker and copy every listing URL. One person often has several.",
  "Submit that site’s opt-out. Confirm the email or phone code the same day. Do not upload a Social Security card.",
  "After the listing is down, ask Google to drop the cached result. Search removal does not delete the broker’s copy.",
  "If you live in California, file one DROP request, then still opt out of the people-search sites DROP does not cover.",
  "Look again in a few months. A new public record can put the listing back.",
  "If a form is ignored, send the letter below to the site’s privacy contact and keep the confirmation.",
];

export function deletionLetter(target: string, kind: string): string {
  return removalLetter({ target, kind });
}

export function removalLetter(input: {
  target: string;
  kind: string;
  name?: string;
  email?: string;
  listingUrl?: string;
  broker?: string;
}): string {
  const today = new Date().toISOString().slice(0, 10);
  const who = input.name?.trim() || input.target;
  const listing = input.listingUrl?.trim();
  const email = input.email?.trim();
  return `Subject: Please delete personal information

Date: ${today}

I am requesting that you delete the personal information you publish about ${who} (${input.kind}${input.broker ? `, ${input.broker}` : ""}), including any people-search profile, cached copy, and resale of that profile.
${listing ? `\nListing: ${listing}\n` : ""}
Please remove the public listing, stop selling or resharing it, and confirm in writing when that is done.${email ? ` Reply to ${email}.` : ""} Do not ask me to send a Social Security number.

I am authorized to make this request. It does not ask you to hide a crime, alter a court record the law requires you to keep, or delete someone else’s information without their permission.

Thank you.`;
}

/** Mailto for a broker that publishes a privacy mailbox. Returns null when this broker has no such address. */
export function removalMailto(
  link: RemovalLink,
  input: { name: string; email: string; listingUrl: string; target: string; kind: string },
): string | null {
  if (!link.mail) return null;
  const body = removalLetter({ ...input, broker: link.title });
  const subject = `Delete my listing on ${link.title}`;
  return `mailto:${link.mail}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export function listingMatches(link: RemovalLink, listingUrl: string): boolean {
  if (!link.hosts?.length) return true;
  try {
    const host = new URL(listingUrl).hostname.replace(/^www\./, "").toLowerCase();
    return link.hosts.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
  } catch {
    return false;
  }
}

/** The broker whose site this listing URL is on, if we know that site. */
export function matchBroker(listingUrl: string): RemovalLink | null {
  const url = listingUrl.trim();
  if (!url) return null;
  return TAKEDOWN_LINKS.find((link) => link.hosts?.length && listingMatches(link, url)) ?? null;
}

