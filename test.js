let ws_url = new URL(document.URL);
ws_url.protocol = "ws:";
ws_url.pathname = "/ws";
const socket = new WebSocket(ws_url);

function journal_msg(msg) {
	let journal = document.getElementById("journal");
	let div = document.createElement("div");
	div.innerText = msg;
	journal.prepend(div);

	return div;
}

socket.addEventListener("open", (event) => {
	socket.send("init");
});

let ws_counter = 0;
let ws_conns = new Object();

socket.addEventListener("message", (event) => {
	console.log("MSG: ", event.data);
	if ((m = event.data.match(/^connect (.*)/))) {
		const url = m[1];
		let req = new XMLHttpRequest();
		req.onload = (e) => {
			console.log(`XHR complete for ${url}`);
			socket.send(`complete ${url}`);
			journal_msg(`complete ${url}`).style.color = "#060";
		};
		req.ontimeout = () => {
			console.log(`XHR timeout for ${url}`);
			socket.send(`timeout ${url}`);
			journal_msg(`timeout ${url}`).style.color = "#a06";
		};
		req.onerror = (e) => {
			console.log(`XHR error for ${url}: ${req.statusText}`);
			socket.send(`error ${url} ${req.statusText}`);
			journal_msg(`error ${url} ${req.statusText}`).style.color = "#f00";
		};
		req.open("GET", url, true);
		req.timeout = 1000; /* ms */
		console.log(`XHR send ${url}`);
		journal_msg(`connecting ${url}`);
		req.send();
	} else if ((m = event.data.match(/^ws-connect (.*)/))) {
		const url = m[1];

		console.log(`WS connecting ${url}`);
		journal_msg(`WS connecting ${url}`);

		const wsock = new WebSocket(url);
		let num = ++ws_counter;

		ws_conns[num] = wsock;

		wsock.addEventListener("open", (event) => {
			socket.send(`ws-connected ${num} ${url}`);
			console.log(`WS connected ${url}`);
			journal_msg(`WS connected ${url}`);
		});
	} else if ((m = event.data.match(/^ws-send (.*)/))) {
		const num = parseInt(m[1]);
		const wsock = ws_conns[num];

		console.log(`WS ping #${num}`);
		journal_msg(`WS ping #${num}`);
		wsock.send("ping");
	} else if ((m = event.data.match(/^ws-close (.*)/))) {
		const num = parseInt(m[1]);
		const wsock = ws_conns[num];

		console.log(`WS close #${num}`);
		journal_msg(`WS close #${num}`);
		wsock.close();
	} else if ((m = event.data.match(/^message (.*)/))) {
		const msg = m[1];
		journal_msg(`message: ${msg}`).style.color = "#00c";
	} else if ((m = event.data.match(/^passfail ([^ ]+) (.*)/))) {
		const which = m[1];
		const msg = m[2];
		journal_msg(`${which}: ${msg}`).classList.add(`res-${which}`);
	} else if ((m = event.data.match(/^manual (.*)/))) {
		const addr = m[1];
		let manual = document.getElementById("manual");
		manual.innerText = `please ssh/connect to ${addr}`;
		manual.style.display = "block";
	} else if ((m = event.data.match(/^manual-clear/))) {
		let manual = document.getElementById("manual");
		manual.innerText = "";
		manual.style.display = "none";
	} else {
		journal_msg(`unknown: ${event.data}`).style.color = "#f00";
	}
});

socket.addEventListener("close", (event) => {
	console.log(`WS closed ${event.reason}`);
	journal_msg(`control connection closed (${event.reason})`).style.backgroundColor = "#ccf";
});

socket.addEventListener("error", (event) => {
	console.log("WS error");
	journal_msg("control connection error").style.backgroundColor = "#fad";
});
