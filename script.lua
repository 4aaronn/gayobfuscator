
--[[
    ETHIC CUSTOM OBF v2.1
    Large Script Edition
    Target: Roblox Luau
    Profile: Balanced

    Improvements:
      - Chunk-aware source scanning
      - Buffered token output
      - Chunked constant-pool serialization
      - XOR string encryption
      - Runtime integrity verification
      - Randomized identifiers
      - Configurable processing limits
      - No arbitrary source-size limit

    Usage:
      local obfuscate = require(path.to.ethic_custom_obf)

      local output, stats = obfuscate(source, {
          watermark = "ETHIC PRIVATE",
          chunkSize = 65536,
          bufferSize = 4096,
          poolChunkSize = 4096
      })
]]

local ETHIC = {}

local MOD = 2147483647

-- ==========================================
-- CONFIGURATION
-- ==========================================

local DEFAULTS = {
    watermark = "ETHIC CUSTOM OBF v2.1",
    chunkSize = 65536,
    bufferSize = 4096,
    poolChunkSize = 4096,
}

-- ==========================================
-- RANDOM IDENTIFIERS
-- ==========================================

local function randomIdentifier()
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local result = "__E"

    for i = 1, math.random(15, 24) do
        local index = math.random(1, #chars)
        result = result .. chars:sub(index, index)
    end

    return result
end

local function uniqueIdentifier(used)
    local name

    repeat
        name = randomIdentifier()
    until not used[name]

    used[name] = true

    return name
end

-- ==========================================
-- CHARACTER HELPERS
-- ==========================================

local function isLetter(c)
    return c ~= "" and c:match("[%a_]") ~= nil
end

local function isDigit(c)
    return c ~= "" and c:match("%d") ~= nil
end

local function isIdentifierPart(c)
    return c ~= "" and c:match("[%w_]") ~= nil
end

local function isWhitespace(c)
    return c ~= "" and c:match("%s") ~= nil
end

-- ==========================================
-- LONG BRACKET STRINGS / COMMENTS
-- ==========================================

local function longBracketOpen(source, position)
    if source:sub(position, position) ~= "[" then
        return nil
    end

    local cursor = position + 1

    while source:sub(cursor, cursor) == "=" do
        cursor = cursor + 1
    end

    if source:sub(cursor, cursor) == "[" then
        return cursor - position - 1, cursor + 1
    end

    return nil
end

local function longBracketEnd(source, position)
    local equals, contentStart = longBracketOpen(source, position)

    if equals == nil then
        return nil
    end

    local closing = "]" .. string.rep("=", equals) .. "]"
    local finish = source:find(closing, contentStart, true)

    if not finish then
        return #source + 1
    end

    return finish + #closing
end

-- ==========================================
-- STRING DECODER
-- ==========================================

local function decodeQuotedString(token)
    local quote = token:sub(1, 1)

    if quote ~= '"' and quote ~= "'" then
        return nil
    end

    if token:sub(-1) ~= quote then
        return nil
    end

    local output = {}
    local i = 2
    local finish = #token - 1

    while i <= finish do
        local c = token:sub(i, i)

        if c ~= "\\" then
            output[#output + 1] = c
            i = i + 1
        else
            i = i + 1

            if i > finish then
                return nil
            end

            local e = token:sub(i, i)

            local escapes = {
                a = "\7",
                b = "\8",
                f = "\12",
                n = "\n",
                r = "\r",
                t = "\t",
                v = "\11",
                ["\\"] = "\\",
                ['"'] = '"',
                ["'"] = "'",
            }

            if escapes[e] then
                output[#output + 1] = escapes[e]
                i = i + 1

            elseif e == "\n" then
                output[#output + 1] = "\n"
                i = i + 1

            elseif e == "\r" then
                output[#output + 1] = "\n"
                i = i + 1

                if token:sub(i, i) == "\n" then
                    i = i + 1
                end

            elseif e == "z" then
                i = i + 1

                while i <= finish and isWhitespace(token:sub(i, i)) do
                    i = i + 1
                end

            elseif e == "x" then
                local hex = token:sub(i + 1, i + 2)

                if not hex:match("^%x%x$") then
                    return nil
                end

                output[#output + 1] = string.char(tonumber(hex, 16))
                i = i + 3

            elseif isDigit(e) then
                local digits = token:sub(i, i + 2)
                local number = digits:match("^%d%d?%d?")

                if not number then
                    return nil
                end

                local value = tonumber(number)

                if value > 255 then
                    return nil
                end

                output[#output + 1] = string.char(value)
                i = i + #number

            else
                return nil
            end
        end
    end

    return table.concat(output)
end

-- ==========================================
-- CHUNKED TOKENIZER
-- ==========================================

local function tokenize(source, encoder, chunkSize, bufferSize)
    local outputChunks = {}
    local outputBuffer = {}

    local cursor = 1
    local length = #source

    local encryptedStrings = 0
    local identifiers = {}

    local bufferCount = 0
    local chunkCount = 0

    local function emit(value)
        bufferCount = bufferCount + 1
        outputBuffer[bufferCount] = value

        if bufferCount >= bufferSize then
            chunkCount = chunkCount + 1
            outputChunks[chunkCount] = table.concat(outputBuffer)

            table.clear(outputBuffer)
            bufferCount = 0
        end
    end

    local function flush()
        if bufferCount > 0 then
            chunkCount = chunkCount + 1
            outputChunks[chunkCount] = table.concat(outputBuffer)

            table.clear(outputBuffer)
            bufferCount = 0
        end
    end

    local chunkStart = 1

    while chunkStart <= length do
        local chunkEnd = math.min(
            chunkStart + chunkSize - 1,
            length
        )

        -- Tokens may extend beyond chunkEnd.
        -- The lexer always finishes the current token
        -- before advancing to the next processing chunk.

        while cursor <= chunkEnd do
            local c = source:sub(cursor, cursor)
            local nextChar = source:sub(cursor + 1, cursor + 1)

            -- Whitespace
            if isWhitespace(c) then
                local start = cursor

                repeat
                    cursor = cursor + 1
                    c = source:sub(cursor, cursor)
                until not isWhitespace(c)

                emit(source:sub(start, cursor - 1))

            -- Comments
            elseif c == "-" and nextChar == "-" then
                local equals = longBracketOpen(source, cursor + 2)

                if equals ~= nil then
                    local ending = longBracketEnd(source, cursor + 2)

                    emit(source:sub(cursor, ending - 1))
                    cursor = ending
                else
                    local ending = source:find("\n", cursor, true)

                    if not ending then
                        emit(source:sub(cursor))
                        cursor = length + 1
                    else
                        emit(source:sub(cursor, ending - 1))
                        cursor = ending
                    end
                end

            -- Quoted strings
            elseif c == '"' or c == "'" then
                local start = cursor
                local quote = c

                cursor = cursor + 1

                while cursor <= length do
                    local current = source:sub(cursor, cursor)

                    if current == "\\" then
                        cursor = cursor + 2

                    elseif current == quote then
                        cursor = cursor + 1
                        break

                    elseif current == "\n" or current == "\r" then
                        break

                    else
                        cursor = cursor + 1
                    end
                end

                local token = source:sub(start, cursor - 1)
                local decoded = decodeQuotedString(token)

                if decoded ~= nil then
                    emit(encoder(decoded))
                    encryptedStrings = encryptedStrings + 1
                else
                    emit(token)
                end

            -- Long bracket strings
            elseif c == "[" then
                local ending = longBracketEnd(source, cursor)

                if ending then
                    emit(source:sub(cursor, ending - 1))
                    cursor = ending
                else
                    emit(c)
                    cursor = cursor + 1
                end

            -- Backtick interpolation strings
            elseif c == "`" then
                local start = cursor
                cursor = cursor + 1

                while cursor <= length do
                    local current = source:sub(cursor, cursor)

                    if current == "\\" then
                        cursor = cursor + 2
                    elseif current == "`" then
                        cursor = cursor + 1
                        break
                    else
                        cursor = cursor + 1
                    end
                end

                emit(source:sub(start, cursor - 1))

            -- Identifiers
            elseif isLetter(c) then
                local start = cursor
                cursor = cursor + 1

                while cursor <= length and
                    isIdentifierPart(source:sub(cursor, cursor)) do

                    cursor = cursor + 1
                end

                local identifier = source:sub(start, cursor - 1)

                identifiers[identifier] = true
                emit(identifier)

            -- Other characters
            else
                emit(c)
                cursor = cursor + 1
            end
        end

        flush()

        chunkStart = chunkEnd + 1
    end

    flush()

    return table.concat(outputChunks),
        identifiers,
        encryptedStrings,
        chunkCount
end

-- ==========================================
-- XOR ENCRYPTION
-- ==========================================

local function encrypt(value, key)
    local result = {}

    for i = 1, #value do
        result[i] = bit32.bxor(value:byte(i), key)
    end

    return result
end

-- ==========================================
-- CHECKSUM
-- ==========================================

local function checksum(pool)
    local sum = 0

    for i = 1, #pool do
        sum = (sum + ((i * pool[i]) % MOD)) % MOD
    end

    return sum
end

-- ==========================================
-- CONSTANT POOL SERIALIZER
-- ==========================================

local function serializePool(pool, chunkSize)
    local chunks = {}
    local current = {}

    local count = 0
    local chunkCount = 0

    for i = 1, #pool do
        count = count + 1
        current[count] = tostring(pool[i])

        if count >= chunkSize then
            chunkCount = chunkCount + 1
            chunks[chunkCount] = table.concat(current, ",")

            table.clear(current)
            count = 0
        end
    end

    if count > 0 then
        chunkCount = chunkCount + 1
        chunks[chunkCount] = table.concat(current, ",")
    end

    return "{" .. table.concat(chunks, ",") .. "}", chunkCount
end

-- ==========================================
-- MAIN ENGINE
-- ==========================================

function ETHIC.obfuscate(source, options)
    options = options or {}

    if type(source) ~= "string" then
        return nil, "ETHIC: source must be a string"
    end

    local config = {}

    for key, value in pairs(DEFAULTS) do
        config[key] = value
    end

    for key, value in pairs(options) do
        config[key] = value
    end

    for _, key in ipairs({
        "chunkSize",
        "bufferSize",
        "poolChunkSize"
    }) do
        local value = config[key]

        if type(value) ~= "number"
            or value < 256
            or value % 1 ~= 0 then

            return nil, "ETHIC: invalid " .. key
        end
    end

    if type(config.watermark) ~= "string" then
        return nil, "ETHIC: invalid watermark"
    end

    local started = os.clock()

    local pool = {}
    local used = {}

    local encryptedBytes = 0
    local stringCount = 0

    -- Generated identifiers
    local poolName = uniqueIdentifier(used)
    local decoderName = uniqueIdentifier(used)
    local checksumName = uniqueIdentifier(used)
    local expectedName = uniqueIdentifier(used)

    local indexName = uniqueIdentifier(used)
    local sumName = uniqueIdentifier(used)
    local offsetName = uniqueIdentifier(used)
    local lengthName = uniqueIdentifier(used)
    local keyName = uniqueIdentifier(used)
    local charName = uniqueIdentifier(used)

    -- String encoder
    local function encodeString(value)
        local key = math.random(1, 255)
        local encrypted = encrypt(value, key)

        local offset = #pool + 1
        local count = #encrypted

        for i = 1, count do
            pool[#pool + 1] = encrypted[i]
        end

        encryptedBytes = encryptedBytes + count
        stringCount = stringCount + 1

        return decoderName .. "("
            .. offset .. ","
            .. count .. ","
            .. key .. ")"
    end

    -- Chunk-aware transformation
    local transformed, identifiers, _, sourceChunks =
        tokenize(
            source,
            encodeString,
            config.chunkSize,
            config.bufferSize
        )

    -- Verify generated identifiers
    for name in pairs(identifiers) do
        if used[name] then
            return nil, "ETHIC: identifier collision; retry obfuscation"
        end
    end

    -- Serialize encrypted pool in chunks
    local poolSource, poolChunks =
        serializePool(pool, config.poolChunkSize)

    local expectedChecksum = checksum(pool)

    -- Watermark
    local header = "--[[\n"
        .. "    " .. config.watermark .. "\n"
        .. "    ETHIC CUSTOM OBF v2.1\n"
        .. "]]\n\n"

    -- Runtime integrity verification and decoder
    local prelude = "local " .. poolName .. " = " .. poolSource .. "\n\n"

    prelude = prelude .. "local " .. expectedName
        .. " = " .. expectedChecksum .. "\n\n"

    prelude = prelude .. [[
local ]] .. checksumName .. [[ = function()
    local ]] .. sumName .. [[ = 0

    for ]] .. indexName .. [[ = 1, #]] .. poolName .. [[ do
        local b = ]] .. poolName .. "[" .. indexName .. [[

        if type(b) ~= "number" or b < 0 or b > 255 then
            error("ETHIC: integrity verification failed", 0)
        end

        ]] .. sumName .. [[ = (]] .. sumName .. [[ +
            (]] .. indexName .. [[ * b) % 2147483647
        ) % 2147483647
    end

    return ]] .. sumName .. [[
end

if ]] .. checksumName .. [[() ~= ]] .. expectedName .. [[ then
    error("ETHIC: source integrity verification failed", 0)
end

local ]] .. decoderName .. [[ = function(
    ]] .. offsetName .. [[,
    ]] .. lengthName .. [[,
    ]] .. keyName .. [[
)
    if type(]] .. offsetName .. [[) ~= "number"
        or type(]] .. lengthName .. [[) ~= "number"
        or type(]] .. keyName .. [[) ~= "number" then

        error("ETHIC: invalid decoder arguments", 0)
    end

    if ]] .. offsetName .. [[ < 1
        or ]] .. lengthName .. [[ < 0
        or ]] .. offsetName .. [[ + ]] .. lengthName .. [[ - 1 > #]] .. poolName .. [[
        or ]] .. keyName .. [[ < 1
        or ]] .. keyName .. [[ > 255 then

        error("ETHIC: invalid encrypted string", 0)
    end

    local result = table.create(]] .. lengthName .. [[)

    for ]] .. indexName .. [[ = 1, ]] .. lengthName .. [[ do
        local ]] .. charName .. [[ = bit32.bxor(
            ]] .. poolName .. "[" .. offsetName .. " + " .. indexName .. " - 1],
            ]] .. keyName .. [[
        )

        result[]] .. indexName .. [[] = string.char(]] .. charName .. [[)
    end

    return table.concat(result)
end

]]

    local output = header .. prelude .. transformed

    local stats = {
        version = "2.1",
        target = "Roblox Luau",
        profile = "Balanced",

        originalSize = #source,
        outputSize = #output,

        encryptedStrings = stringCount,
        encryptedBytes = encryptedBytes,

        constantPoolSize = #pool,
        sourceChunks = sourceChunks,
        poolChunks = poolChunks,

        checksum = expectedChecksum,
        elapsed = os.clock() - started,
    }

    return output, stats
end

return ETHIC.obfuscate
