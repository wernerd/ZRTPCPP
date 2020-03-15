/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _ZRTPTEXTDATA_H_
#define _ZRTPTEXTDATA_H_

/**
 * @file ZrtpTextData.h
 * @brief The ZRTP ASCII texts - extern references
 *  
 * @ingroup ZRTP
 * @{
 */

#include <common/osSpecifics.h>

/**
 * Fixed strings.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

constexpr char clientId[] =    "GNU ZRTP 5.0.0  "; // 16 chars max.
constexpr char zrtpVersion_11[] = "1.10";          // must be 4 chars
constexpr char zrtpVersion_12[] = "1.20";          // must be 4 chars
/**
 *
 */
constexpr char HelloMsg[]    = "Hello   ";
constexpr char HelloAckMsg[] = "HelloACK";
constexpr char CommitMsg[]   = "Commit  ";
constexpr char DHPart1Msg[]  = "DHPart1 ";
constexpr char DHPart2Msg[]  = "DHPart2 ";
constexpr char Confirm1Msg[] = "Confirm1";
constexpr char Confirm2Msg[] = "Confirm2";
constexpr char Conf2AckMsg[] = "Conf2ACK";
constexpr char ErrorMsg[]    = "Error   ";
constexpr char ErrorAckMsg[] = "ErrorACK";
constexpr char GoClearMsg[]  = "GoClear ";
constexpr char ClearAckMsg[] = "ClearACK";
constexpr char PingMsg[]     = "Ping    ";
constexpr char PingAckMsg[]  = "PingACK ";
constexpr char SasRelayMsg[] = "SASrelay";
constexpr char RelayAckMsg[] = "RelayACK";

constexpr char responder[]      = "Responder";
constexpr char initiator[]      = "Initiator";
constexpr char iniMasterKey[]   = "Initiator SRTP master key";
constexpr char iniMasterSalt[]  = "Initiator SRTP master salt";
constexpr char respMasterKey[]  = "Responder SRTP master key";
constexpr char respMasterSalt[] = "Responder SRTP master salt";

constexpr char iniHmacKey[]  = "Initiator HMAC key";
constexpr char respHmacKey[] = "Responder HMAC key";
constexpr char retainedSec[] = "retained secret";

constexpr char iniZrtpKey[]  = "Initiator ZRTP key";
constexpr char respZrtpKey[] = "Responder ZRTP key";

constexpr char sasString[] = "SAS";

constexpr char KDFString[] = "ZRTP-HMAC-KDF";

constexpr char zrtpSessionKey[] = "ZRTP Session Key";
constexpr char zrtpExportedKey[] = "Exported key";

constexpr char zrtpMsk[] = "ZRTP MSK";
constexpr char zrtpTrustedMitm[] = "Trusted MiTM key";

// Make these constants accessible to external functions
constexpr char s256[] = "S256";        //!< SHA-256 hash
constexpr char s384[] = "S384";        //!< SHA-384 hash
constexpr char skn2[] = "SKN2";        //!< Skein-256 hash (https://en.wikipedia.org/wiki/Skein_(hash_function))
constexpr char skn3[] = "SKN3";        //!< Skein-384 hash (https://en.wikipedia.org/wiki/Skein_(hash_function))
constexpr const char* mandatoryHash = s256;

constexpr char aes3[] = "AES3";        //!< AES symmetric cipher with 256 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
constexpr char aes2[] = "AES2";        //!< AES symmetric cipher with 192 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
constexpr char aes1[] = "AES1";        //!< AES symmetric cipher with 128 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
constexpr char two3[] = "2FS3";        //!< Twofish symmetric cipher with 256 bit key length, use to enrypt/decrypt media data
constexpr char two2[] = "2FS2";        //!< Twofish symmetric cipher with 192 bit key length, use to enrypt/decrypt media data
constexpr char two1[] = "2FS1";        //!< Twofish symmetric cipher with 128 bit key length, use to enrypt/decrypt media data
constexpr const char* mandatoryCipher = aes1;

constexpr char dh2k[] = "DH2k";        //!< Diffie-Hellman using a 2048 bit finite field, see RFC3526 - not recommended anymore
constexpr char ec25[] = "EC25";        //!< Diffie-Hellman using the NIST Elliptic Curve defined by FIPS 186-2, P-256
constexpr char dh3k[] = "DH3k";        //!< Diffie-Hellman using a 3072 bit finite field, see RFC3526
constexpr char ec38[] = "EC38";        //!< Diffie-Hellman using the NIST Elliptic Curve defined by FIPS 186-2, P-384
constexpr char e255[] = "E255";        //!< Diffie-Hellman using Curve EC25519 (see https://safecurves.cr.yp.to/equation.html)
constexpr char e414[] = "E414";        //!< Diffie-Hellman using Curve41417 (see https://safecurves.cr.yp.to/equation.html), optional
constexpr char sdh5[] = "SDH5";        //!< SIDH 503 algorithm, allegedly Quantum safe (see https://github.com/microsoft/PQCrypto-SIDH), optional, experimental
constexpr char sdh7[] = "SDH7";        //!< SIDH 751 algorithm, allegedly Quantum safe (see https://github.com/microsoft/PQCrypto-SIDH), optional, experimental
constexpr char mult[] = "Mult";        //!< Multi-stream, required if applications like to avoid additional key negotiation when using several encrypted media streams
constexpr const char* mandatoryPubKey = dh3k;

constexpr char b32[] =  "B32 ";        //!< Use 4 characters to show the SAS
constexpr char b256[] = "B256";        //!< Use two words to show the SAS
constexpr char b32e[] = "B32E";        //!< Use selected Emojis instead of letters/digits
constexpr char b10d[] = "B10D";        //!< Use 6 digits, this may be used for international SAS values
constexpr const char* mandatorySasType = b32;

constexpr char hs32[] = "HS32";        //!< Use 32-bits of HMAC-SHA1 as authentication tag for SRTP (see RFC3711, sections 3.1, 3.4)
constexpr char hs80[] = "HS80";        //!< Use 80-bits of HMAC-SHA1 as authentication tag for SRTP (see RFC3711, sections 3.1, 3.4)
constexpr char sk32[] = "SK32";        //!< Use 32-bits of HMAC-Skein as authentication for tag SRTP (non-standard)
constexpr char sk64[] = "SK64";        //!< Use 80-bits of HMAC-Skein as authentication for tag SRTP (non-standard)
constexpr const char* mandatoryAuthLen_1 = hs32;
constexpr const char* mandatoryAuthLen_2 = hs80;

constexpr char const * sas256WordsOdd[] = {
        "adroitness",
        "adviser",
        "aftermath",
        "aggregate",
        "alkali",
        "almighty",
        "amulet",
        "amusement",
        "antenna",
        "applicant",
        "Apollo",
        "armistice",
        "article",
        "asteroid",
        "Atlantic",
        "atmosphere",
        "autopsy",
        "Babylon",
        "backwater",
        "barbecue",
        "belowground",
        "bifocals",
        "bodyguard",
        "bookseller",
        "borderline",
        "bottomless",
        "Bradbury",
        "bravado",
        "Brazilian",
        "breakaway",
        "Burlington",
        "businessman",
        "butterfat",
        "Camelot",
        "candidate",
        "cannonball",
        "Capricorn",
        "caravan",
        "caretaker",
        "celebrate",
        "cellulose",
        "certify",
        "chambermaid",
        "Cherokee",
        "Chicago",
        "clergyman",
        "coherence",
        "combustion",
        "commando",
        "company",
        "component",
        "concurrent",
        "confidence",
        "conformist",
        "congregate",
        "consensus",
        "consulting",
        "corporate",
        "corrosion",
        "councilman",
        "crossover",
        "crucifix",
        "cumbersome",
        "customer",
        "Dakota",
        "decadence",
        "December",
        "decimal",
        "designing",
        "detector",
        "detergent",
        "determine",
        "dictator",
        "dinosaur",
        "direction",
        "disable",
        "disbelief",
        "disruptive",
        "distortion",
        "document",
        "embezzle",
        "enchanting",
        "enrollment",
        "enterprise",
        "equation",
        "equipment",
        "escapade",
        "Eskimo",
        "everyday",
        "examine",
        "existence",
        "exodus",
        "fascinate",
        "filament",
        "finicky",
        "forever",
        "fortitude",
        "frequency",
        "gadgetry",
        "Galveston",
        "getaway",
        "glossary",
        "gossamer",
        "graduate",
        "gravity",
        "guitarist",
        "hamburger",
        "Hamilton",
        "handiwork",
        "hazardous",
        "headwaters",
        "hemisphere",
        "hesitate",
        "hideaway",
        "holiness",
        "hurricane",
        "hydraulic",
        "impartial",
        "impetus",
        "inception",
        "indigo",
        "inertia",
        "infancy",
        "inferno",
        "informant",
        "insincere",
        "insurgent",
        "integrate",
        "intention",
        "inventive",
        "Istanbul",
        "Jamaica",
        "Jupiter",
        "leprosy",
        "letterhead",
        "liberty",
        "maritime",
        "matchmaker",
        "maverick",
        "Medusa",
        "megaton",
        "microscope",
        "microwave",
        "midsummer",
        "millionaire",
        "miracle",
        "misnomer",
        "molasses",
        "molecule",
        "Montana",
        "monument",
        "mosquito",
        "narrative",
        "nebula",
        "newsletter",
        "Norwegian",
        "October",
        "Ohio",
        "onlooker",
        "opulent",
        "Orlando",
        "outfielder",
        "Pacific",
        "pandemic",
        "Pandora",
        "paperweight",
        "paragon",
        "paragraph",
        "paramount",
        "passenger",
        "pedigree",
        "Pegasus",
        "penetrate",
        "perceptive",
        "performance",
        "pharmacy",
        "phonetic",
        "photograph",
        "pioneer",
        "pocketful",
        "politeness",
        "positive",
        "potato",
        "processor",
        "provincial",
        "proximate",
        "puberty",
        "publisher",
        "pyramid",
        "quantity",
        "racketeer",
        "rebellion",
        "recipe",
        "recover",
        "repellent",
        "replica",
        "reproduce",
        "resistor",
        "responsive",
        "retraction",
        "retrieval",
        "retrospect",
        "revenue",
        "revival",
        "revolver",
        "sandalwood",
        "sardonic",
        "Saturday",
        "savagery",
        "scavenger",
        "sensation",
        "sociable",
        "souvenir",
        "specialist",
        "speculate",
        "stethoscope",
        "stupendous",
        "supportive",
        "surrender",
        "suspicious",
        "sympathy",
        "tambourine",
        "telephone",
        "therapist",
        "tobacco",
        "tolerance",
        "tomorrow",
        "torpedo",
        "tradition",
        "travesty",
        "trombonist",
        "truncated",
        "typewriter",
        "ultimate",
        "undaunted",
        "underfoot",
        "unicorn",
        "unify",
        "universe",
        "unravel",
        "upcoming",
        "vacancy",
        "vagabond",
        "vertigo",
        "Virginia",
        "visitor",
        "vocalist",
        "voyager",
        "warranty",
        "Waterloo",
        "whimsical",
        "Wichita",
        "Wilmington",
        "Wyoming",
        "yesteryear",
        "Yucatan"
};

constexpr char const * sas256WordsEven[] = {
        "aardvark",
        "absurd",
        "accrue",
        "acme",
        "adrift",
        "adult",
        "afflict",
        "ahead",
        "aimless",
        "Algol",
        "allow",
        "alone",
        "ammo",
        "ancient",
        "apple",
        "artist",
        "assume",
        "Athens",
        "atlas",
        "Aztec",
        "baboon",
        "backfield",
        "backward",
        "banjo",
        "beaming",
        "bedlamp",
        "beehive",
        "beeswax",
        "befriend",
        "Belfast",
        "berserk",
        "billiard",
        "bison",
        "blackjack",
        "blockade",
        "blowtorch",
        "bluebird",
        "bombast",
        "bookshelf",
        "brackish",
        "breadline",
        "breakup",
        "brickyard",
        "briefcase",
        "Burbank",
        "button",
        "buzzard",
        "cement",
        "chairlift",
        "chatter",
        "checkup",
        "chisel",
        "choking",
        "chopper",
        "Christmas",
        "clamshell",
        "classic",
        "classroom",
        "cleanup",
        "clockwork",
        "cobra",
        "commence",
        "concert",
        "cowbell",
        "crackdown",
        "cranky",
        "crowfoot",
        "crucial",
        "crumpled",
        "crusade",
        "cubic",
        "dashboard",
        "deadbolt",
        "deckhand",
        "dogsled",
        "dragnet",
        "drainage",
        "dreadful",
        "drifter",
        "dropper",
        "drumbeat",
        "drunken",
        "Dupont",
        "dwelling",
        "eating",
        "edict",
        "egghead",
        "eightball",
        "endorse",
        "endow",
        "enlist",
        "erase",
        "escape",
        "exceed",
        "eyeglass",
        "eyetooth",
        "facial",
        "fallout",
        "flagpole",
        "flatfoot",
        "flytrap",
        "fracture",
        "framework",
        "freedom",
        "frighten",
        "gazelle",
        "Geiger",
        "glitter",
        "glucose",
        "goggles",
        "goldfish",
        "gremlin",
        "guidance",
        "hamlet",
        "highchair",
        "hockey",
        "indoors",
        "indulge",
        "inverse",
        "involve",
        "island",
        "jawbone",
        "keyboard",
        "kickoff",
        "kiwi",
        "klaxon",
        "locale",
        "lockup",
        "merit",
        "minnow",
        "miser",
        "Mohawk",
        "mural",
        "music",
        "necklace",
        "Neptune",
        "newborn",
        "nightbird",
        "Oakland",
        "obtuse",
        "offload",
        "optic",
        "orca",
        "payday",
        "peachy",
        "pheasant",
        "physique",
        "playhouse",
        "Pluto",
        "preclude",
        "prefer",
        "preshrunk",
        "printer",
        "prowler",
        "pupil",
        "puppy",
        "python",
        "quadrant",
        "quiver",
        "quota",
        "ragtime",
        "ratchet",
        "rebirth",
        "reform",
        "regain",
        "reindeer",
        "rematch",
        "repay",
        "retouch",
        "revenge",
        "reward",
        "rhythm",
        "ribcage",
        "ringbolt",
        "robust",
        "rocker",
        "ruffled",
        "sailboat",
        "sawdust",
        "scallion",
        "scenic",
        "scorecard",
        "Scotland",
        "seabird",
        "select",
        "sentence",
        "shadow",
        "shamrock",
        "showgirl",
        "skullcap",
        "skydive",
        "slingshot",
        "slowdown",
        "snapline",
        "snapshot",
        "snowcap",
        "snowslide",
        "solo",
        "southward",
        "soybean",
        "spaniel",
        "spearhead",
        "spellbind",
        "spheroid",
        "spigot",
        "spindle",
        "spyglass",
        "stagehand",
        "stagnate",
        "stairway",
        "standard",
        "stapler",
        "steamship",
        "sterling",
        "stockman",
        "stopwatch",
        "stormy",
        "sugar",
        "surmount",
        "suspense",
        "sweatband",
        "swelter",
        "tactics",
        "talon",
        "tapeworm",
        "tempest",
        "tiger",
        "tissue",
        "tonic",
        "topmost",
        "tracker",
        "transit",
        "trauma",
        "treadmill",
        "Trojan",
        "trouble",
        "tumor",
        "tunnel",
        "tycoon",
        "uncut",
        "unearth",
        "unwind",
        "uproot",
        "upset",
        "upshot",
        "vapor",
        "village",
        "virus",
        "Vulcan",
        "waffle",
        "wallet",
        "watchword",
        "wayside",
        "willow",
        "woodlark",
        "Zulu"
};

/**
 * @}
 */
#endif     // _ZRTPTEXTDATA_H_

