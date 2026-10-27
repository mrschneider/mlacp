#!/usr/bin/env node
// MLACP cross-language client (Node.js) — speaks the wire vocabulary of the
// Python reference node. This file IS the interop claim: a client in another
// language drives the protocol end to end.
//
// Usage: node client.js <port> <scenario> [<arg>]
//   scenario "ping"        — bind two services, envelope ping-pong
//   scenario "custody"     — offline addressee: custody taken, dumped on return
//   scenario "refusals"    — unknown verb refused by name; bad urn refused
//   scenario "register"    — register an offline service in the directory
const net = require("net");

function connect(port) {
  const sock = net.connect(port, "127.0.0.1");
  const client = { sock, buf: "", waiters: [] };
  sock.setEncoding("utf8");
  sock.on("data", (chunk) => {
    client.buf += chunk;
    let idx;
    while ((idx = client.buf.indexOf("\n")) >= 0) {
      const line = client.buf.slice(0, idx);
      client.buf = client.buf.slice(idx + 1);
      if (client.waiters.length) client.waiters.shift()(JSON.parse(line));
    }
  });
  client.send = (obj) => sock.write(JSON.stringify(obj) + "\n");
  client.recv = (ms = 5000) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("timeout waiting frame")), ms);
      client.waiters.push((f) => { clearTimeout(t); resolve(f); });
    });
  client.close = () => sock.destroy();
  return client;
}

const hello = (urn, caps) => ({ kind: "hello", v: "1.0", urn, capabilities: caps || [] });
const envelope = (sender, recipient, seq, body) =>
  ({ kind: "envelope", v: "1.0", sender, recipient, seq, ttl: 16, body });

async function main() {
  const [port, scenario, arg] = [parseInt(process.argv[2]), process.argv[3], process.argv[4]];
  const A = "mlacp:ministry/north/ct-1/dispatch";
  const B = "mlacp:ministry/north/ct-1/relay";
  const results = [];
  const ok = (name, cond) => { results.push([name, cond]); console.log(`${cond ? "PASS" : "FAIL"}: ${name}`); };

  if (scenario === "register") {
    // bind as the offline service so the directory knows it, then leave
    const c = connect(port);
    c.send(hello(B));
    const r2 = await c.recv();
    ok("register: hello answered with the node urn", r2.kind === "hello" && r2.urn === arg);
    ok("register: directory contains the relay service", r2.directory.includes(B));
    c.close();
  } else if (scenario === "ping") {
    const ca = connect(port), cb = connect(port);
    ca.send(hello(A)); const ra = await ca.recv();
    cb.send(hello(B)); const rb = await cb.recv();
    ok("ping: both bound", ra.kind === "hello" && rb.kind === "hello");
    ca.send(envelope(A, B, 1, { text: "ping" }));
    const delivered = await cb.recv();
    ok("ping: envelope crossed the node", delivered.kind === "envelope" && delivered.body.text === "ping");
    cb.send(envelope(B, A, 1, { text: "pong" }));
    const back = await ca.recv();
    ok("ping: pong came back", back.kind === "envelope" && back.body.text === "pong");
    ca.close(); cb.close();
  } else if (scenario === "custody") {
    // A connects; B is registered-but-offline (registered by the orchestrator)
    const ca = connect(port);
    ca.send(hello(A)); await ca.recv();
    ca.send(envelope(A, B, 1, { text: "hold this for the relay" }));
    const ack = await ca.recv();
    ok("custody: node took custody and acked", ack.kind === "custody_ack" && ack.status === "held");
    ca.close();
    // B comes back on the air
    const cb = connect(port);
    cb.send(hello(B));
    const dumped = await cb.recv();
    ok("custody: dump on re-registration", dumped.kind === "envelope" && dumped.body.text === "hold this for the relay");
    // acknowledge: release custody
    cb.send({ kind: "custody_ack", v: "1.0", bundle_id: `bndl-${A}-1`, status: "released" });
    cb.close();
  } else if (scenario === "federate") {
    // arg: the local center urn; B (the peer-homed service) is passed as args[1]
    const localUrn = arg;
    const peerSvc = process.argv[5];
    const ca = connect(port);
    ca.send(hello(A));
    const ra = await ca.recv();
    ok("federate: bound at the local center", ra.kind === "hello");
    ca.send(envelope(A, peerSvc, 1, { text: "cross-center hello" }));
    const ack = await ca.recv();
    ok("federate: hop answered with a custody_ack",
       ack.kind === "custody_ack" && (ack.status === "delivered" || ack.status === "held"));
    ca.close();
  } else if (scenario === "refusals") {
    const c = connect(port);
    c.send(hello(A)); await c.recv();
    c.send({ kind: "agent_step", v: "1.0" });
    const e1 = await c.recv();
    ok("refusals: unknown verb named and listed",
       e1.kind === "error" && e1.code === "unknownkind" && e1.message.includes("envelope"));
    c.send(envelope(A, "MLACP:BAD/URN", 1, {}));
    const e2 = await c.recv();
    ok("refusals: bad address refused", e2.kind === "error" && e2.code !== "internal");
    c.close();
  }

  const fails = results.filter(([, c]) => !c).length;
  console.log(`CLIENT_${scenario.toUpperCase()}: ${fails === 0 ? "PASS" : "FAIL"}`);
  process.exit(fails === 0 ? 0 : 1);
}

main().catch((e) => { console.error("CLIENT_ERROR:", e.message); process.exit(2); });
