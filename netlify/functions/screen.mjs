import { MongoClient } from "mongodb";

let cachedClient = null;

async function getDb() {
    if (!cachedClient) {
        const uri = process.env.MONGODB_URI;
        if (!uri) {
            throw new Error("MONGODB_URI environment variable is not set on the server");
        }
        const client = new MongoClient(uri);
        await client.connect();
        cachedClient = client;
    }
    return cachedClient.db("test");
}

export default async (req) => {
    // Handle CORS preflight
    if (req.method === "OPTIONS") {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
            }
        });
    }

    const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
    };

    try {
        const db = await getDb();

        // 1. Validate API Key
        const apiKey = req.headers.get("x-api-key");
        if (!apiKey) {
            return new Response(JSON.stringify({ error: "Missing X-API-Key header" }), { status: 401, headers });
        }

        const keyDoc = await db.collection("api_keys").findOne({ key: apiKey, active: true });
        if (!keyDoc) {
            return new Response(JSON.stringify({ error: "Invalid or inactive API key" }), { status: 403, headers });
        }

        // 2. Enforce Daily Rate Limit (atomic increment per key per UTC day)
        const today = new Date().toISOString().slice(0, 10); // e.g., "2026-11-26"
        const dailyLimit = keyDoc.daily_limit || 500;

        const usage = await db.collection("rate_limits").findOneAndUpdate(
            { key: apiKey, date: today },
            { $inc: { count: 1 } },
            { upsert: true, returnDocument: "after" }
        );

        if (usage.count > dailyLimit) {
            return new Response(
                JSON.stringify({ error: "Daily rate limit exceeded", limit: dailyLimit, reset: "00:00 UTC" }),
                { status: 429, headers }
            );
        }

        // 3. Parse Search Parameters (supports GET query params or POST JSON body)
        let name, birthDate, country;
        if (req.method === "POST") {
            const body = await req.json();
            name = body.name;
            birthDate = body.birth_date;
            country = body.country;
        } else {
            const url = new URL(req.url);
            name = url.searchParams.get("name");
            birthDate = url.searchParams.get("birth_date");
            country = url.searchParams.get("country");
        }

        if (!name || !name.trim()) {
            return new Response(JSON.stringify({ error: "Missing 'name' parameter" }), { status: 400, headers });
        }

        // 4. Build Fuzzy Atlas Search Query
        const shouldClauses = [
            {
                text: {
                    query: name.trim(),
                    path: ["name", "aliases"],
                    fuzzy: { maxEdits: 2, prefixLength: 1 },
                    score: { boost: { value: 3 } }
                }
            }
        ];

        if (birthDate) {
            shouldClauses.push({
                text: {
                    query: birthDate.trim(),
                    path: "birth_date",
                    fuzzy: { maxEdits: 1 },
                    score: { boost: { value: 2 } }
                }
            });
        }

        if (country) {
            shouldClauses.push({
                text: {
                    query: country.trim().toLowerCase(),
                    path: "countries",
                    score: { boost: { value: 1.5 } }
                }
            });
        }

        const results = await db.collection("sanctions").aggregate([
            {
                $search: {
                    index: "sanctions_search",
                    compound: {
                        should: shouldClauses,
                        minimumShouldMatch: 1
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    id: 1,
                    schema: 1,
                    name: 1,
                    aliases: 1,
                    birth_date: 1,
                    countries: 1,
                    dataset: 1,
                    score: { $meta: "searchScore" }
                }
            },
            { $limit: 10 }
        ]).toArray();

        // 5. Write Compliance Audit Log (non-blocking)
        await db.collection("audit_logs").insertOne({
            timestamp: new Date(),
            client_name: keyDoc.owner || "unknown",
            api_key_prefix: apiKey.slice(0, 10) + "...",
            query: { name, birth_date: birthDate || null, country: country || null },
            match_count: results.length,
            top_match_id: results[0]?.id || null,
            top_score: results[0]?.score || 0
        });

        return new Response(
            JSON.stringify({
                query: { name, birth_date: birthDate || null, country: country || null },
                remaining_quota: Math.max(0, dailyLimit - usage.count),
                count: results.length,
                results
            }),
            { status: 200, headers }
        );
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
};

export const config = {
    path: "/api/screen"
};
