const state = {
  masterHex: "",
  namespace: "",
  selectedId: "master",
  filter: "all",
  sourceMode: "master",
  sourceParentId: "",
  manualParentKeyHex: "",
  manualParentPath: "",
  nodes: [],
  commandLog: []
};

const trunkNodes = [
  {
    id: "master",
    label: "Master Secret",
    path: "offline-root",
    branch: "Root",
    type: "MasterSecret",
    action: "init",
    trunk: true,
    children: ["trust-root"]
  },
  {
    id: "trust-root",
    label: "Trust Root",
    path: "PCA/V1/TrustRoot",
    branch: "Root",
    type: "TrustRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: ["identity-branch", "encryption-branch"]
  },
  {
    id: "identity-branch",
    label: "Identity Branch",
    path: "Identity/V1/Root",
    branch: "Identity",
    type: "BranchRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: ["identity-root", "pca-identity"]
  },
  {
    id: "identity-root",
    label: "Identity Root",
    path: "Identity/V1/Root",
    branch: "Identity",
    type: "IdentityRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: []
  },
  {
    id: "pca-identity",
    label: "PCA Infrastructure",
    path: "Identity/V1/PCA",
    branch: "Identity",
    type: "InfrastructureIdentity",
    action: "identity",
    trunk: true,
    children: []
  },
  {
    id: "encryption-branch",
    label: "Encryption Branch",
    path: "Encrypt/V1/Root",
    branch: "Encryption",
    type: "BranchRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: ["generation-root", "vault-root"]
  },
  {
    id: "generation-root",
    label: "Generation Root",
    path: "Encrypt/V1/Generation",
    branch: "Encryption",
    type: "GenerationRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: ["password-manager", "bitcoin-mainnet"]
  },
  {
    id: "password-manager",
    label: "Password Manager",
    path: "Encrypt/V1/Generation/PasswordManager",
    branch: "Encryption",
    type: "GenerationKey",
    action: "generation",
    length: 32,
    trunk: true,
    children: []
  },
  {
    id: "bitcoin-mainnet",
    label: "Bitcoin Mainnet",
    path: "Encrypt/V1/Generation/Bitcoin/Mainnet",
    branch: "Encryption",
    type: "BIP32Seed",
    action: "bip32-seed",
    trunk: true,
    children: []
  },
  {
    id: "vault-root",
    label: "Vault Root",
    path: "Encrypt/V1/Vault/Root",
    branch: "Encryption",
    type: "VaultRoot",
    action: "derive-node",
    length: 64,
    trunk: true,
    children: []
  }
];

const dynamicChildren = new Map();
const collapsed = new Set();

const tree = document.querySelector("#tree");
const namespaceLine = document.querySelector("#namespaceLine");
const selectedDetails = document.querySelector("#selectedDetails");
const sourceControls = document.querySelector("#sourceControls");
const forms = document.querySelector("#forms");
const commandLog = document.querySelector("#commandLog");
const initButton = document.querySelector("#initButton");
const resetButton = document.querySelector("#resetButton");
const clearLog = document.querySelector("#clearLog");
const nodeCount = document.querySelector("#nodeCount");

function resetState() {
  state.masterHex = "";
  state.namespace = "";
  state.selectedId = "master";
  state.nodes = trunkNodes.map((node) => ({ ...node, generated: false, result: null }));
  state.sourceMode = "master";
  state.sourceParentId = "";
  state.manualParentKeyHex = "";
  state.manualParentPath = "";
  state.commandLog = [];
  dynamicChildren.clear();
  collapsed.clear();
  render();
}

function nodeById(id) {
  return state.nodes.find((node) => node.id === id);
}

function childrenFor(node) {
  return [...(node.children || []), ...(dynamicChildren.get(node.id) || [])]
    .map(nodeById)
    .filter(Boolean);
}

function canShow(node) {
  return state.filter === "all" || node.branch === state.filter || node.branch === "Root";
}

function render() {
  namespaceLine.textContent = state.namespace ? `Namespace: ${state.namespace}` : "Namespace: not initialized";
  nodeCount.textContent = `${state.nodes.length} nodes`;
  initButton.textContent = state.masterHex ? "Regenerate Master" : "Generate Master";
  tree.replaceChildren(renderNode(nodeById("master")));
  renderDetails();
  renderSourceControls();
  renderForms();
  renderLog();
}

function renderNode(node) {
  const wrapper = document.createElement("div");
  wrapper.className = "node-wrap";
  if (!canShow(node)) {
    wrapper.hidden = true;
    return wrapper;
  }

  const row = document.createElement("div");
  row.className = "node-row";

  const childNodes = childrenFor(node);
  const toggle = document.createElement("button");
  toggle.className = "toggle";
  toggle.type = "button";
  toggle.textContent = childNodes.length ? (collapsed.has(node.id) ? "+" : "-") : "";
  toggle.disabled = childNodes.length === 0;
  toggle.addEventListener("click", (event) => {
    event.stopPropagation();
    if (collapsed.has(node.id)) collapsed.delete(node.id);
    else collapsed.add(node.id);
    render();
  });
  row.append(toggle);

  const button = document.createElement("button");
  button.type = "button";
  button.className = [
    "node-button",
    node.trunk ? "trunk" : "dynamic",
    node.generated ? "ready" : "",
    node.branch,
    state.selectedId === node.id ? "selected" : ""
  ].join(" ");
  button.addEventListener("click", () => selectNode(node.id));

  const label = document.createElement("span");
  label.innerHTML = `<span class="node-title"></span><span class="node-path"></span>`;
  label.querySelector(".node-title").textContent = node.label;
  label.querySelector(".node-path").textContent = node.path;

  const badge = document.createElement("span");
  badge.className = ["badge", node.generated ? "ready" : "trunk", node.branch].join(" ");
  badge.textContent = node.generated ? "generated" : node.trunk ? "preset" : node.type;

  button.append(label, badge);
  row.append(button);
  wrapper.append(row);

  if (childNodes.length && !collapsed.has(node.id)) {
    const children = document.createElement("div");
    children.className = "node-children";
    childNodes.forEach((child) => children.append(renderNode(child)));
    wrapper.append(children);
  }

  return wrapper;
}

function renderDetails() {
  const node = nodeById(state.selectedId);
  selectedDetails.replaceChildren();
  const entries = [
    ["Type", node.type],
    ["Branch", node.branch],
    ["Path", node.path],
    ["State", node.generated ? "generated" : "preset"],
    ["Action", node.action]
  ];
  for (const [key, value] of entries) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value || "-";
    selectedDetails.append(dt, dd);
  }

  const run = document.createElement("button");
  run.className = "primary";
  run.type = "button";
  run.textContent = node.action === "init" ? "Generate" : "Run";
  run.addEventListener("click", () => runNodeAction(node));
  const dt = document.createElement("dt");
  dt.textContent = "CLI";
  const dd = document.createElement("dd");
  dd.append(run);
  selectedDetails.append(dt, dd);
}

function renderSourceControls() {
  sourceControls.replaceChildren();

  const namespace = input(state.namespace);
  namespace.placeholder = "PCA-v1/<NamespaceID>";
  namespace.addEventListener("input", () => {
    state.namespace = namespace.value;
    namespaceLine.textContent = state.namespace ? `Namespace: ${state.namespace}` : "Namespace: not initialized";
  });
  sourceControls.append(field("Namespace", namespace));

  const mode = select(["MasterSecret", "SelectedParent", "ManualParent"]);
  mode.value =
    state.sourceMode === "selected" ? "SelectedParent" : state.sourceMode === "manual" ? "ManualParent" : "MasterSecret";
  mode.addEventListener("change", () => {
    state.sourceMode =
      mode.value === "SelectedParent" ? "selected" : mode.value === "ManualParent" ? "manual" : "master";
    render();
  });
  sourceControls.append(field("Mode", mode));

  if (state.sourceMode === "selected") {
    const candidates = generatedParentCandidates();
    const parent = document.createElement("select");
    candidates.forEach((node) => {
      const item = document.createElement("option");
      item.value = node.id;
      item.textContent = `${node.label} | ${node.path}`;
      parent.append(item);
    });
    if (!state.sourceParentId && candidates.length) {
      state.sourceParentId = candidates[0].id;
    }
    parent.value = state.sourceParentId;
    parent.disabled = candidates.length === 0;
    parent.addEventListener("change", () => {
      state.sourceParentId = parent.value;
    });
    sourceControls.append(field("Parent node", parent));
    if (!candidates.length) {
      const note = document.createElement("p");
      note.className = "node-path";
      note.textContent = "Generate a node first";
      sourceControls.append(note);
    }
  }

  if (state.sourceMode === "manual") {
    const key = input(state.manualParentKeyHex);
    const path = input(state.manualParentPath || "Encrypt/V1/Vault/Finance");
    key.placeholder = "Uppercase HEX parent key";
    path.placeholder = "Parent Canonical Info Path";
    key.addEventListener("input", () => {
      state.manualParentKeyHex = key.value;
    });
    path.addEventListener("input", () => {
      state.manualParentPath = path.value;
    });
    sourceControls.append(field("Parent key", key), field("Parent path", path));
  }
}

function renderForms() {
  const node = nodeById(state.selectedId);
  forms.replaceChildren();
  if (node.branch === "Identity" || node.id === "identity-branch") {
    forms.append(identityForm());
  }
  if (node.id === "generation-root" || node.type === "GenerationRoot") {
    forms.append(generationForm());
  }
  if (node.id === "vault-root" || node.type === "VaultRoot" || node.type === "VaultPermission") {
    forms.append(vaultForm(node));
  }
  if (!forms.childElementCount) {
    const empty = document.createElement("p");
    empty.className = "node-path";
    empty.textContent = "No branch form";
    forms.append(empty);
  }
}

function field(label, input) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  wrap.append(lab, input);
  return wrap;
}

function identityForm() {
  const form = document.createElement("form");
  form.className = "form-grid";
  form.innerHTML = "";
  const persona = input("Personal");
  const identity = input("Identity2026");
  const usage = input("ProfileKey");
  const submit = button("Add Identity");
  form.append(field("Persona", persona), field("Identity", identity), field("Usage", usage), submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const path = `Identity/V1/${persona.value}/${identity.value}/${usage.value}`;
    await createDynamicNode({
      parentId: "identity-branch",
      label: usage.value,
      path,
      branch: "Identity",
      type: "IdentityNode",
      action: "identity"
    });
  });
  return form;
}

function generationForm() {
  const form = document.createElement("form");
  form.className = "form-grid";
  const path = input("Encrypt/V1/Generation/APIKeys/GitHub");
  const length = select(["32", "64"]);
  const submit = button("Add Generation");
  form.append(field("Path", path), field("Length", length), submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await createDynamicNode({
      parentId: "generation-root",
      label: path.value.split("/").slice(-1)[0],
      path: path.value,
      branch: "Encryption",
      type: "GenerationKey",
      action: "generation",
      length: Number(length.value)
    });
  });
  return form;
}

function vaultForm(node) {
  const form = document.createElement("form");
  form.className = "form-grid";
  const mode = select(["PermissionNode", "FileKey"]);
  const permission = input(node.type === "VaultPermission" ? node.permissionPath : "Finance/2026/Q3");
  const fileId = input("");
  fileId.placeholder = "optional Uppercase HEX";
  const submit = button("Add Vault Node");
  form.append(field("Mode", mode), field("Permission", permission), field("File ID", fileId), submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (mode.value === "PermissionNode") {
      await createDynamicNode({
        parentId: "vault-root",
        label: permission.value.split("/").slice(-1)[0],
        path: `Encrypt/V1/Vault/${permission.value}`,
        permissionPath: permission.value,
        branch: "Encryption",
        type: "VaultPermission",
        action: "vault-permission"
      });
    } else {
      await createDynamicNode({
        parentId: node.type === "VaultPermission" ? node.id : "vault-root",
        label: "FileKey",
        path: `Encrypt/V1/Vault/${permission.value}/${fileId.value || "NewFileId"}`,
        permissionPath: permission.value,
        fileId: fileId.value,
        branch: "Encryption",
        type: "VaultFileKey",
        action: "vault-file-key"
      });
    }
  });
  return form;
}

function input(value) {
  const el = document.createElement("input");
  el.value = value;
  return el;
}

function select(options) {
  const el = document.createElement("select");
  options.forEach((option) => {
    const item = document.createElement("option");
    item.value = option;
    item.textContent = option;
    el.append(item);
  });
  return el;
}

function button(text) {
  const el = document.createElement("button");
  el.type = "submit";
  el.className = "primary";
  el.textContent = text;
  return el;
}

async function createDynamicNode(definition) {
  const node = {
    id: `node-${crypto.randomUUID()}`,
    trunk: false,
    generated: false,
    result: null,
    children: [],
    ...definition
  };
  state.nodes.push(node);
  const siblings = dynamicChildren.get(node.parentId) || [];
  siblings.push(node.id);
  dynamicChildren.set(node.parentId, siblings);
  state.selectedId = node.id;
  render();
  await runNodeAction(node);
}

function selectNode(id) {
  state.selectedId = id;
  render();
}

async function runNodeAction(node) {
  if (node.action !== "init" && state.sourceMode === "master" && (!state.masterHex || !state.namespace)) {
    const initResponse = await runCli("init", {});
    if (!initResponse.ok || !initResponse.data) return;
    state.masterHex = initResponse.data.master_secret_hex;
    state.namespace = initResponse.data.namespace;
    const master = nodeById("master");
    master.generated = true;
    master.result = initResponse.data;
  }
  const payload = payloadFor(node);
  const response = await runCli(node.action, payload);
  if (!response.ok) return;
  const data = response.data;
  if (node.action === "init" && data) {
    state.masterHex = data.master_secret_hex;
    state.namespace = data.namespace;
  }
  node.generated = true;
  node.result = data;
  if (node.type === "VaultFileKey" && data && data.file_id) {
    node.fileId = data.file_id;
    node.path = data.path;
    node.label = `File ${data.file_id.slice(0, 8)}`;
  }
  render();
}

function payloadFor(node) {
  const base = sourcePayload();
  if (node.action === "derive-node") return { ...base, path: node.path, length: node.length || 64 };
  if (node.action === "identity") return { ...base, path: node.path };
  if (node.action === "generation") return { ...base, path: node.path, length: node.length || 32 };
  if (node.action === "bip32-seed") return { ...base, network: "Mainnet" };
  if (node.action === "vault-permission") return { ...base, permission_path: node.permissionPath };
  if (node.action === "vault-file-key") {
    return { ...base, permission_path: node.permissionPath, file_id: node.fileId || "" };
  }
  return {};
}

function sourcePayload() {
  const base = { namespace: state.namespace };
  if (state.sourceMode === "selected") {
    const parent = nodeById(state.sourceParentId);
    const key = parent ? nodeKeyHex(parent) : "";
    return { ...base, parent_key_hex: key, parent_path: parent?.path || "" };
  }
  if (state.sourceMode === "manual") {
    return { ...base, parent_key_hex: state.manualParentKeyHex, parent_path: state.manualParentPath };
  }
  return { ...base, master_hex: state.masterHex };
}

function generatedParentCandidates() {
  return state.nodes.filter((node) => node.generated && nodeKeyHex(node) && node.path !== "offline-root");
}

function nodeKeyHex(node) {
  if (!node || !node.result || typeof node.result !== "object") return "";
  return node.result.key_hex || node.result.seed_hex || "";
}

async function runCli(action, payload) {
  const response = await fetch("/api/cli", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, payload })
  });
  const result = await response.json();
  state.commandLog.unshift({
    action,
    time: new Date().toLocaleTimeString(),
    ...result
  });
  renderLog();
  return result;
}

function renderLog() {
  commandLog.replaceChildren();
  const template = document.querySelector("#commandEntryTemplate");
  state.commandLog.forEach((entry) => {
    const item = template.content.cloneNode(true);
    item.querySelector(".entry-meta").textContent = `${entry.time}  ${entry.action}  ${entry.ok ? "ok" : "failed"}`;
    item.querySelector(".entry-command").textContent = entry.command || entry.error || "";
    const output = item.querySelector(".entry-output");
    output.textContent = entry.stdout || entry.stderr || entry.error || JSON.stringify(entry.data, null, 2);
    if (!entry.ok) output.classList.add("error");
    commandLog.append(item);
  });
}

document.querySelectorAll(".segment").forEach((segment) => {
  segment.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
    segment.classList.add("active");
    state.filter = segment.dataset.filter;
    render();
  });
});

initButton.addEventListener("click", () => runNodeAction(nodeById("master")));
resetButton.addEventListener("click", resetState);
clearLog.addEventListener("click", () => {
  state.commandLog = [];
  renderLog();
});

resetState();
