async def run():
    await phase("scan", title="Scan")
    r = await agent("find bugs", label="scanner")
    s = await agent("same default label prompt that is long enough to be cut off here")
    s2 = await agent("same default label prompt that is long enough to be cut off here")
    v = await verify_finding({"id": "F1", "title": "x"})
    out = await pipeline([1, 2, 3, 4], lambda x: 1 / (x - 2), lambda y: [y, y])
    return {"findings": [v], "pipeline": out}
