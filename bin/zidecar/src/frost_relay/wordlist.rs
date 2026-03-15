// human-readable room codes: 3 random words from a curated list.
// 256 words → 256^3 = 16M combinations. rooms expire in minutes
// so collision probability is negligible.

use rand::Rng;

const WORDS: &[&str] = &[
    "acid", "aged", "also", "area", "army", "away", "baby", "back", "ball", "band",
    "bank", "base", "bath", "bear", "beat", "been", "bell", "best", "bird", "bite",
    "blow", "blue", "boat", "body", "bomb", "bond", "bone", "book", "born", "boss",
    "both", "burn", "busy", "cafe", "cage", "cake", "call", "calm", "came", "camp",
    "cape", "card", "care", "case", "cash", "cast", "cave", "chat", "chip", "city",
    "clay", "club", "coal", "coat", "code", "cold", "come", "cook", "cool", "cope",
    "copy", "core", "cost", "crew", "crop", "curl", "cute", "dare", "dark", "data",
    "dawn", "dead", "deal", "dear", "deep", "deny", "desk", "dial", "diet", "dirt",
    "dish", "disk", "dock", "dome", "done", "door", "dose", "down", "draw", "drop",
    "drum", "dual", "duke", "dump", "dust", "duty", "each", "earn", "ease", "east",
    "easy", "edge", "edit", "else", "epic", "even", "ever", "evil", "exam", "exit",
    "face", "fact", "fail", "fair", "fall", "fame", "farm", "fast", "fate", "fear",
    "feed", "feel", "fell", "file", "fill", "film", "find", "fine", "fire", "firm",
    "fish", "five", "flag", "flat", "fled", "flew", "flip", "flow", "foam", "fold",
    "folk", "fond", "font", "food", "foot", "ford", "form", "fort", "foul", "four",
    "free", "from", "fuel", "full", "fund", "fury", "fuse", "gain", "game", "gang",
    "gate", "gave", "gaze", "gear", "gene", "gift", "girl", "give", "glad", "glow",
    "glue", "goal", "goes", "gold", "golf", "gone", "good", "grab", "gray", "grew",
    "grid", "grip", "grow", "gulf", "guru", "gust", "half", "hall", "halt", "hand",
    "hang", "hard", "harm", "harp", "hash", "hate", "have", "haze", "head", "heap",
    "hear", "heat", "held", "help", "herb", "here", "hero", "hide", "high", "hike",
    "hill", "hint", "hire", "hold", "hole", "holy", "home", "hood", "hook", "hope",
    "horn", "host", "hour", "huge", "hung", "hunt", "hurt", "hymn", "icon", "idea",
    "idle", "inch", "info", "into", "iron", "item", "jack", "jade", "jail", "jazz",
    "jean", "jest", "join", "joke", "jump", "jury", "just", "keen", "keep", "kelp",
    "kept", "kick", "kind", "king", "kiss", "kite",
];

pub fn generate_room_code() -> String {
    let mut rng = rand::thread_rng();
    let w1 = WORDS[rng.gen_range(0..WORDS.len())];
    let w2 = WORDS[rng.gen_range(0..WORDS.len())];
    let w3 = WORDS[rng.gen_range(0..WORDS.len())];
    format!("{}-{}-{}", w1, w2, w3)
}
