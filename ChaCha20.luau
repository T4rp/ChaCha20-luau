local U32_MOD = 2 ^ 32

local function qr(buff: buffer, a, b, c, d)
	c = c * 4
	b = b * 4
	a = a * 4
	d = d * 4

	local av = buffer.readu32(buff, a)
	local bv = buffer.readu32(buff, b)
	local cv = buffer.readu32(buff, c)
	local dv = buffer.readu32(buff, d)

	av += bv
	av %= U32_MOD
	dv = bit32.bxor(dv, av)
	dv = bit32.lrotate(dv, 16)

	cv += dv
	cv %= U32_MOD
	bv = bit32.bxor(bv, cv)
	bv = bit32.lrotate(bv, 12)

	av += bv
	av %= U32_MOD
	dv = bit32.bxor(dv, av)
	dv = bit32.lrotate(dv, 8)

	cv += dv
	cv %= U32_MOD
	bv = bit32.bxor(bv, cv)
	bv = bit32.lrotate(bv, 7)

	buffer.writeu32(buff, a, av)
	buffer.writeu32(buff, b, bv)
	buffer.writeu32(buff, c, cv)
	buffer.writeu32(buff, d, dv)
end

local x = buffer.create(16 * 4)
local function chacha20Core(out: buffer, inp: buffer)
	buffer.copy(x, 0, inp, 0, 16 * 4)

	for _ = 1, 10 do
		qr(x, 0, 4, 8, 12)
		qr(x, 1, 5, 9, 13)
		qr(x, 2, 6, 10, 14)
		qr(x, 3, 7, 11, 15)
		qr(x, 0, 5, 10, 15)
		qr(x, 1, 6, 11, 12)
		qr(x, 2, 7, 8, 13)
		qr(x, 3, 4, 9, 14)
	end

	for i = 0, 15 do
		local sum = buffer.readu32(x, i * 4) + buffer.readu32(inp, i * 4)
		buffer.writeu32(out, i * 4, sum % U32_MOD)
	end
end

type ChaCha20Ctx = {
	block: buffer,
	key: { number },
	nonce: { number },
	counter: number,
	out: buffer,
	index: number,
}

local function newCtx(key: { number }, nonce: { number }): ChaCha20Ctx
	local block = buffer.create(16 * 4)
	local counter = 1

	buffer.writeu32(block, 0 * 4, 0x61707865)
	buffer.writeu32(block, 1 * 4, 0x3320646e)
	buffer.writeu32(block, 2 * 4, 0x79622d32)
	buffer.writeu32(block, 3 * 4, 0x6b206574)

	for i = 0, 7 do
		buffer.writeu32(block, (4 + i) * 4, key[i + 1])
	end

	buffer.writeu32(block, 12 * 4, counter)
	buffer.writeu32(block, 13 * 4, nonce[1])
	buffer.writeu32(block, 14 * 4, nonce[2])
	buffer.writeu32(block, 15 * 4, nonce[3])

	local out = buffer.create(16 * 4)

	return {
		block = block,
		out = out,
		key = key,
		nonce = nonce,
		counter = counter,
		index = 0,
	}
end

local function genBlock(ctx: ChaCha20Ctx)
	buffer.writeu32(ctx.block, 12 * 4, ctx.counter)
	chacha20Core(ctx.out, ctx.block)
end

local function nextBlock(ctx: ChaCha20Ctx)
	ctx.index = 0
	ctx.counter += 1
	buffer.writeu32(ctx.block, 12 * 4, ctx.counter)
end

local function xorBuffer(ctx: ChaCha20Ctx, buf: buffer)
	local bufLength = buffer.len(buf)
	local out = ctx.out

	for i = 0, bufLength - 1 do
		local xord = bit32.bxor(buffer.readu8(buf, i), buffer.readu8(out, ctx.index))
		buffer.writeu8(buf, i, xord)
		ctx.index += 1

		if ctx.index % 64 == 0 then
			nextBlock(ctx)
			genBlock(ctx)
		end
	end
end

return {
	newCtx = newCtx,
	genBlock = genBlock,
	nextBlock = nextBlock,
	xorBuffer = xorBuffer,
}
