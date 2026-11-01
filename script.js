"use strict";

const passwordOutput = document.querySelector("#password-output");
const sourcePasswordInput = document.querySelector("#source-password");
const lengthSlider = document.querySelector("#length-slider");
const lengthValue = document.querySelector("#length-value");
const strengthText = document.querySelector("#strength-text");
const strengthMeter = document.querySelector("#strength-meter");
const formMessage = document.querySelector("#form-message");
const generateButton = document.querySelector("#generate-button");
const regenerateButton = document.querySelector("#regenerate-button");
const copyButton = document.querySelector("#copy-button");
const saveButton = document.querySelector("#save-button");
const visibilityButton = document.querySelector("#visibility-button");
const passwordNoteInput = document.querySelector("#password-note");
const passwordCategorySelect = document.querySelector("#password-category");
const vaultAccessForm = document.querySelector("#vault-access");
const vaultPassphraseInput = document.querySelector("#vault-passphrase");
const vaultPassphraseLabel = document.querySelector("#vault-passphrase-label");
const vaultAccessButton = document.querySelector("#vault-access-button");
const vaultHint = document.querySelector("#vault-hint");
const vaultUnlocked = document.querySelector("#vault-unlocked");
const vaultLockButton = document.querySelector("#vault-lock-button");
const vaultEntriesContainer = document.querySelector("#vault-entries");
const vaultMessage = document.querySelector("#vault-message");
const vaultSearchInput = document.querySelector("#vault-search");
const vaultCategoryFilter = document.querySelector("#vault-category-filter");
const categoryCreateForm = document.querySelector("#category-create-form");
const newCategoryInput = document.querySelector("#new-category");

const vaultStorageKey = "keysmith.encryptedVault.v1";
const vaultIterations = 310000;
const defaultCategories = ["Personal", "Work", "Education", "Banking", "Social Media"];
let vaultKey = null;
let vaultEntries = [];
let vaultCategories = [...defaultCategories];
let vaultExists = false;

const characterSets = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?/",
};

function randomInt(max) {
  const range = 0x100000000;
  const limit = range - (range % max);
  const value = new Uint32Array(1);

  do {
    window.crypto.getRandomValues(value);
  } while (value[0] >= limit);

  return value[0] % max;
}

async function createCategory(event) {
  event.preventDefault();
  const category = newCategoryInput.value.trim();
  if (!category) {
    showVaultMessage("Enter a name for the new category.");
    return;
  }
  if (vaultCategories.some((existing) => existing.toLocaleLowerCase() === category.toLocaleLowerCase())) {
    showVaultMessage("That category already exists.");
    newCategoryInput.focus();
    return;
  }

  const updatedCategories = [...vaultCategories, category];
  await updateVaultData(vaultEntries, updatedCategories);
  if (vaultCategories.includes(category)) {
    newCategoryInput.value = "";
    passwordCategorySelect.value = category;
    showVaultMessage(`Category "${category}" added.`, true);
  }
}

async function deleteCategory(category) {
  if (defaultCategories.includes(category)) {
    return;
  }
  if (!window.confirm(`Delete "${category}" and move its passwords to Personal?`)) {
    return;
  }

  const updatedCategories = vaultCategories.filter((existing) => existing !== category);
  const updatedEntries = vaultEntries.map((entry) =>
    entry.category === category ? { ...entry, category: defaultCategories[0] } : entry);
  await updateVaultData(updatedEntries, updatedCategories);
}

function setStrength(password, preservedCount = 0) {
  const detectedSets = [
    /[A-Z]/.test(password) ? characterSets.uppercase : "",
    /[a-z]/.test(password) ? characterSets.lowercase : "",
    /[0-9]/.test(password) ? characterSets.numbers : "",
    /[^A-Za-z0-9]/.test(password) ? characterSets.symbols : "",
  ].filter(Boolean);
  const poolSize = new Set(detectedSets.join("")).size;
  const entropy = (password.length - preservedCount) * Math.log2(poolSize);
  let strength = "Weak";

  if (entropy >= 100) {
    strength = "Strong";
  } else if (entropy >= 60) {
    strength = "Medium";
  }

  strengthText.textContent = strength;
  strengthMeter.dataset.strength = strength;
  strengthMeter.setAttribute("aria-label", `${strength} password strength`);
}

function shuffle(characters) {
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    [characters[index], characters[swapIndex]] = [
      characters[swapIndex],
      characters[index],
    ];
  }
}

function generatePassword(requireSource = false) {
  const selectedCharacterSets = Object.entries(characterSets)
    .filter(([name]) => document.querySelector(`#${name}`).checked);
  const selectedSets = selectedCharacterSets.map(([, characters]) => characters);
  const sourcePassword = sourcePasswordInput.value;
  formMessage.textContent = "";
  formMessage.classList.remove("success");

  if (selectedSets.length === 0) {
    passwordOutput.value = "";
    resetStrength();
    formMessage.textContent = "Choose at least one character type to continue.";
    return;
  }

  if (requireSource && !sourcePassword) {
    formMessage.textContent = "Enter your current password to create an inspired password.";
    sourcePasswordInput.focus();
    return;
  }

  if (!window.crypto || typeof window.crypto.getRandomValues !== "function") {
    formMessage.textContent = "Secure password generation is not available in this browser.";
    return;
  }

  const length = Number(lengthSlider.value);
  const combinedSet = [...new Set(selectedSets.join(""))];
  const allowedSourceCharacters = Array.from(sourcePassword)
    .filter((character) => selectedSets.some((set) => set.includes(character)));
  let preservedFragment = [];

  if (sourcePassword) {
    const maxFragmentLength = Math.min(
      Math.max(4, Math.floor(length / 3)),
      length - selectedCharacterSets.length,
    );
    const recognizableWords = (sourcePassword.match(/[A-Za-z]+/g) || [])
      .filter((word) => Array.from(word).every((character) =>
        selectedSets.some((set) => set.includes(character))));
    const sourceWord = recognizableWords.sort((first, second) => second.length - first.length)[0];
    const sourceFragment = sourceWord ? Array.from(sourceWord) : allowedSourceCharacters;
    const preservedCount = Math.min(sourceFragment.length, maxFragmentLength);

    if (preservedCount > 0) {
      const fragmentStart = randomInt(sourceFragment.length - preservedCount + 1);
      preservedFragment = sourceFragment.slice(fragmentStart, fragmentStart + preservedCount);
    }
  }

  const preservedCount = preservedFragment.length;
  const passwordCharacters = [];
  for (const [, characterSet] of selectedCharacterSets) {
    if (
      !preservedFragment.some((character) => characterSet.includes(character))
      && !passwordCharacters.some((character) => characterSet.includes(character))
    ) {
      passwordCharacters.push(characterSet[randomInt(characterSet.length)]);
    }
  }

  while (passwordCharacters.length < length - preservedCount) {
    passwordCharacters.push(combinedSet[randomInt(combinedSet.length)]);
  }

  shuffle(passwordCharacters);
  if (preservedFragment.length > 0) {
    const insertAt = 1 + randomInt(passwordCharacters.length - 1);
    passwordCharacters.splice(insertAt, 0, ...preservedFragment);
  }

  passwordOutput.value = passwordCharacters.join("");
  setStrength(passwordOutput.value, preservedCount);
  sourcePasswordInput.value = "";
  visibilityButton.textContent = "Show";
  visibilityButton.setAttribute("aria-label", "Show generated password");
  visibilityButton.setAttribute("aria-pressed", "false");
  passwordOutput.type = "password";
}

function resetStrength() {
  strengthText.textContent = "—";
  strengthMeter.removeAttribute("data-strength");
  strengthMeter.setAttribute("aria-label", "No password generated");
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function deriveVaultKey(passphrase, salt) {
  const passphraseKey = await window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: vaultIterations, hash: "SHA-256" },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault(entries, categories, key, salt) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ entries, categories }));
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  return JSON.stringify({
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  });
}

function isVaultEntryList(value) {
  return Array.isArray(value) && value.every((entry) =>
    entry
    && typeof entry.id === "string"
    && typeof entry.note === "string"
    && typeof entry.password === "string"
    && typeof entry.createdAt === "string"
    && (entry.category === undefined || typeof entry.category === "string"));
}

function isVaultData(value) {
  return value
    && typeof value === "object"
    && isVaultEntryList(value.entries)
    && Array.isArray(value.categories)
    && value.categories.every((category) => typeof category === "string");
}

function updateVaultAccessMode() {
  vaultPassphraseLabel.textContent = vaultExists
    ? "Vault passphrase"
    : "Create a vault passphrase";
  vaultPassphraseInput.autocomplete = vaultExists ? "current-password" : "new-password";
  vaultPassphraseInput.minLength = vaultExists ? 1 : 12;
  vaultPassphraseInput.placeholder = vaultExists
    ? "Enter your vault passphrase"
    : "At least 12 characters";
  vaultAccessButton.textContent = vaultExists ? "Unlock vault" : "Create vault";
  vaultHint.textContent = vaultExists
    ? "Your encrypted vault is stored only on this device."
    : "Use a strong passphrase you can remember. It cannot be recovered if you forget it.";
}

function showVaultMessage(message, success = false) {
  vaultMessage.textContent = message;
  vaultMessage.classList.toggle("success", success);
}

function lockVault() {
  vaultKey = null;
  vaultEntries = [];
  vaultCategories = [...defaultCategories];
  vaultUnlocked.hidden = true;
  vaultAccessForm.hidden = false;
  vaultPassphraseInput.value = "";
  vaultSearchInput.value = "";
  vaultEntriesContainer.replaceChildren();
  renderCategoryControls();
  updateVaultAccessMode();
}

function addSelectOptions(select, categories, includeAll = false) {
  select.replaceChildren();
  if (includeAll) {
    const allOption = document.createElement("option");
    allOption.value = "";
    allOption.textContent = "All categories";
    select.append(allOption);
  }
  for (const category of categories) {
    const option = document.createElement("option");
    option.value = category;
    option.textContent = category;
    select.append(option);
  }
}

function renderCategoryControls() {
  const savedCategory = passwordCategorySelect.value;
  const selectedFilter = vaultCategoryFilter.value;
  addSelectOptions(passwordCategorySelect, vaultCategories);
  addSelectOptions(vaultCategoryFilter, vaultCategories, true);

  if (vaultCategories.includes(savedCategory)) {
    passwordCategorySelect.value = savedCategory;
  }
  if (vaultCategories.includes(selectedFilter)) {
    vaultCategoryFilter.value = selectedFilter;
  } else {
    vaultCategoryFilter.value = "";
  }
}

function renderVaultEntries() {
  vaultEntriesContainer.replaceChildren();

  if (vaultEntries.length === 0) {
    const emptyMessage = document.createElement("p");
    emptyMessage.className = "vault-empty";
    emptyMessage.textContent = "Your vault is empty. Save a generated password to add your first entry.";
    vaultEntriesContainer.append(emptyMessage);
  }

  const searchTerm = vaultSearchInput.value.trim().toLocaleLowerCase();
  const selectedCategory = vaultCategoryFilter.value;
  let visibleEntryCount = 0;

  for (const category of vaultCategories) {
    const categoryEntries = vaultEntries.filter((entry) => {
      const entryCategory = entry.category || defaultCategories[0];
      const matchesCategory = !selectedCategory || selectedCategory === entryCategory;
      const matchesSearch = !searchTerm
        || entry.note.toLocaleLowerCase().includes(searchTerm)
        || entryCategory.toLocaleLowerCase().includes(searchTerm);
      return entryCategory === category && matchesCategory && matchesSearch;
    });

    if (categoryEntries.length === 0 && (selectedCategory || searchTerm)) {
      continue;
    }

    const folder = document.createElement("details");
    folder.className = "category-folder";
    folder.open = Boolean(selectedCategory || searchTerm);
    const summary = document.createElement("summary");
    const title = document.createElement("span");
    title.className = "category-folder-title";
    title.textContent = category;
    const count = document.createElement("span");
    count.className = "category-folder-count";
    count.textContent = String(categoryEntries.length);
    summary.append(title, count);
    folder.append(summary);

    const folderContent = document.createElement("div");
    folderContent.className = "category-folder-content";
    if (!defaultCategories.includes(category)) {
      const deleteCategoryButton = document.createElement("button");
      deleteCategoryButton.type = "button";
      deleteCategoryButton.className = "delete-category-button";
      deleteCategoryButton.textContent = "Delete category";
      deleteCategoryButton.addEventListener("click", () => deleteCategory(category));
      folderContent.append(deleteCategoryButton);
    }

    if (categoryEntries.length === 0) {
      const empty = document.createElement("p");
      empty.className = "category-folder-empty";
      empty.textContent = "No passwords in this category yet.";
      folderContent.append(empty);
    } else {
      for (const entry of categoryEntries) {
        folderContent.append(createVaultEntryCard(entry));
      }
    }
    folder.append(folderContent);
    vaultEntriesContainer.append(folder);
    visibleEntryCount += categoryEntries.length;
  }

  if (visibleEntryCount === 0 && vaultEntries.length > 0) {
    const noMatches = document.createElement("p");
    noMatches.className = "vault-empty";
    noMatches.textContent = "No passwords match your search or category filter.";
    vaultEntriesContainer.append(noMatches);
  }
}

function createVaultEntryCard(entry) {
  const card = document.createElement("article");
  card.className = "vault-entry";
  card.dataset.entryId = entry.id;

  const main = document.createElement("div");
  main.className = "vault-entry-main";
  const category = document.createElement("p");
  category.className = "vault-entry-category";
  category.textContent = entry.category || defaultCategories[0];
  const note = document.createElement("p");
  note.className = "vault-entry-note";
  note.textContent = entry.note;
  const password = document.createElement("input");
  password.className = "vault-entry-password";
  password.type = "password";
  password.value = entry.password;
  password.readOnly = true;
  password.autocomplete = "off";
  password.setAttribute("aria-label", `Saved password for ${entry.note}`);
  main.append(category, note, password);

  const actions = document.createElement("div");
  actions.className = "vault-entry-actions";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy";
  copy.addEventListener("click", async () => {
    try {
      await copyText(entry.password);
      showVaultMessage(`Copied password for ${entry.note}.`, true);
    } catch (error) {
      showVaultMessage("Could not copy this password. Please try again.");
      console.error("Unable to copy saved password:", error);
    }
  });

  const view = document.createElement("button");
  view.type = "button";
  view.textContent = "Show";
  view.setAttribute("aria-pressed", "false");
  view.addEventListener("click", () => {
    const isVisible = password.type === "text";
    password.type = isVisible ? "password" : "text";
    view.textContent = isVisible ? "Show" : "Hide";
    view.setAttribute("aria-pressed", String(!isVisible));
  });

  const edit = document.createElement("button");
  edit.type = "button";
  edit.textContent = "Edit";
  edit.addEventListener("click", () => startEntryEdit(entry, card));

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "delete-entry-button";
  remove.textContent = "Delete";
  remove.addEventListener("click", async () => {
    if (!window.confirm(`Delete the saved password for "${entry.note}"?`)) {
      return;
    }
    await updateVaultData(vaultEntries.filter((savedEntry) => savedEntry.id !== entry.id));
  });

  actions.append(copy, view, edit, remove);
  card.append(main, actions);
  return card;
}

function startEntryEdit(entry, card) {
  const main = card.querySelector(".vault-entry-main");
  const note = main.querySelector(".vault-entry-note");
  const form = document.createElement("form");
  form.className = "note-edit-form";
  const input = document.createElement("input");
  input.className = "note-edit-input";
  input.type = "text";
  input.maxLength = 80;
  input.required = true;
  input.value = entry.note;
  input.setAttribute("aria-label", "Edit password note");
  const categorySelect = document.createElement("select");
  categorySelect.className = "note-edit-category";
  categorySelect.setAttribute("aria-label", "Change password category");
  addSelectOptions(categorySelect, vaultCategories);
  categorySelect.value = entry.category || defaultCategories[0];
  const actions = document.createElement("div");
  actions.className = "note-edit-actions";
  const save = document.createElement("button");
  save.type = "submit";
  save.textContent = "Save";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", renderVaultEntries);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const updatedNote = input.value.trim();
    if (!updatedNote) {
      showVaultMessage("A note is required for each saved password.");
      input.focus();
      return;
    }

    await updateVaultData(vaultEntries.map((savedEntry) =>
      savedEntry.id === entry.id
        ? { ...savedEntry, note: updatedNote, category: categorySelect.value }
        : savedEntry));
  });

  actions.append(save, cancel);
  form.append(input, categorySelect, actions);
  main.replaceChild(form, note);
  input.focus();
  input.select();
}

async function updateVaultData(updatedEntries, updatedCategories = vaultCategories) {
  if (!vaultKey) {
    showVaultMessage("Unlock the vault before changing saved entries.");
    return;
  }

  try {
    const envelope = JSON.parse(localStorage.getItem(vaultStorageKey));
    await persistVault(updatedEntries, updatedCategories, vaultKey, base64ToBytes(envelope.salt));
    vaultEntries = updatedEntries;
    vaultCategories = updatedCategories;
    renderCategoryControls();
    renderVaultEntries();
    showVaultMessage("Vault updated.", true);
  } catch (error) {
    showVaultMessage("Could not update the encrypted vault. Your changes were not saved.");
    console.error("Unable to update encrypted password vault:", error);
  }
}

async function persistVault(entries, categories, key, salt) {
  const encryptedVault = await encryptVault(entries, categories, key, salt);
  localStorage.setItem(vaultStorageKey, encryptedVault);
}

async function unlockOrCreateVault(event) {
  event.preventDefault();
  const passphrase = vaultPassphraseInput.value;
  let createdVault = false;
  if (!passphrase) {
    showVaultMessage("Enter your vault passphrase.");
    return;
  }

  if (!window.crypto || !window.crypto.subtle) {
    showVaultMessage("Secure vault encryption is not available in this browser.");
    return;
  }

  vaultAccessButton.disabled = true;
  showVaultMessage("");

  try {
    if (vaultExists) {
      const envelope = JSON.parse(localStorage.getItem(vaultStorageKey));
      if (
        envelope.version !== 1
        || typeof envelope.salt !== "string"
        || typeof envelope.iv !== "string"
        || typeof envelope.ciphertext !== "string"
      ) {
        throw new Error("Stored vault has an unsupported or invalid format.");
      }

      const salt = base64ToBytes(envelope.salt);
      const key = await deriveVaultKey(passphrase, salt);
      let plaintext;
      try {
        plaintext = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
          key,
          base64ToBytes(envelope.ciphertext),
        );
      } catch {
        showVaultMessage("That passphrase did not unlock the vault.");
        return;
      }

      const decryptedData = JSON.parse(new TextDecoder().decode(plaintext));
      const isLegacyVault = Array.isArray(decryptedData);
      if (!isLegacyVault && !isVaultData(decryptedData)) {
        throw new Error("Decrypted vault entries have an invalid format.");
      }

      const entries = isLegacyVault ? decryptedData : decryptedData.entries;
      const categories = isLegacyVault
        ? [...defaultCategories]
        : [...new Set([...defaultCategories, ...decryptedData.categories])];
      const migratedEntries = entries.map((entry) => ({
        ...entry,
        category: categories.includes(entry.category) ? entry.category : defaultCategories[0],
      }));

      if (isLegacyVault || migratedEntries.some((entry, index) => entry.category !== entries[index].category)) {
        await persistVault(migratedEntries, categories, key, salt);
      }
      vaultKey = key;
      vaultEntries = migratedEntries;
      vaultCategories = categories;
    } else {
      if (passphrase.length < 12) {
        showVaultMessage("Choose a vault passphrase with at least 12 characters.");
        return;
      }

      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveVaultKey(passphrase, salt);
      await persistVault([], vaultCategories, key, salt);
      vaultKey = key;
      vaultEntries = [];
      vaultCategories = [...defaultCategories];
      vaultExists = true;
      createdVault = true;
    }

    vaultPassphraseInput.value = "";
    vaultAccessForm.hidden = true;
    vaultUnlocked.hidden = false;
    updateVaultAccessMode();
    renderCategoryControls();
    renderVaultEntries();
    showVaultMessage(createdVault ? "Encrypted vault created." : "Vault unlocked.", true);
  } catch (error) {
    showVaultMessage("Could not open the vault. Check browser storage and try again.");
    console.error("Unable to open encrypted password vault:", error);
  } finally {
    vaultAccessButton.disabled = false;
  }
}

async function savePasswordToVault() {
  showVaultMessage("");
  if (!passwordOutput.value) {
    showVaultMessage("Generate a password before saving it.");
    return;
  }
  if (!vaultKey) {
    showVaultMessage("Unlock the Password Vault before saving a password.");
    return;
  }

  const note = passwordNoteInput.value.trim();
  if (!note) {
    showVaultMessage("Add a note describing what this password is for.");
    passwordNoteInput.focus();
    return;
  }

  const idBytes = window.crypto.getRandomValues(new Uint8Array(16));
  const id = Array.from(idBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const entry = {
    id,
    note,
    password: passwordOutput.value,
    category: passwordCategorySelect.value,
    createdAt: new Date().toISOString(),
  };
  await updateVaultData([...vaultEntries, entry]);
  if (vaultEntries.some((savedEntry) => savedEntry.id === id)) {
    passwordNoteInput.value = "";
    showVaultMessage("Password saved in your encrypted vault.", true);
  }
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const temporaryInput = document.createElement("textarea");
  temporaryInput.value = text;
  temporaryInput.setAttribute("readonly", "");
  temporaryInput.style.position = "fixed";
  temporaryInput.style.opacity = "0";
  document.body.append(temporaryInput);
  temporaryInput.select();
  const copied = document.execCommand("copy");
  temporaryInput.remove();

  if (!copied) {
    throw new Error("Clipboard copy was unsuccessful.");
  }
}

function togglePasswordVisibility() {
  const isVisible = passwordOutput.type === "text";
  passwordOutput.type = isVisible ? "password" : "text";
  visibilityButton.textContent = isVisible ? "Show" : "Hide";
  visibilityButton.setAttribute("aria-label", `${isVisible ? "Show" : "Hide"} generated password`);
  visibilityButton.setAttribute("aria-pressed", String(!isVisible));
}

async function copyPassword() {
  if (!passwordOutput.value) {
    formMessage.textContent = "Generate a password before copying it.";
    return;
  }

  try {
    await copyText(passwordOutput.value);

    formMessage.textContent = "Password copied to clipboard.";
    formMessage.classList.add("success");
    copyButton.querySelector("span").textContent = "Copied!";
    window.setTimeout(() => {
      copyButton.querySelector("span").textContent = "Copy";
      formMessage.classList.remove("success");
      formMessage.textContent = "";
    }, 1800);
  } catch (error) {
    formMessage.classList.remove("success");
    formMessage.textContent = "Could not copy automatically. Select and copy the password instead.";
    console.error("Unable to copy password to clipboard:", error);
  }
}

function updateLength() {
  const min = Number(lengthSlider.min);
  const max = Number(lengthSlider.max);
  const value = Number(lengthSlider.value);
  const progress = ((value - min) / (max - min)) * 100;

  lengthValue.value = value;
  lengthValue.textContent = value;
  lengthSlider.style.background = `linear-gradient(to right, #7165e7 0%, #7165e7 ${progress}%, #ebe9f5 ${progress}%, #ebe9f5 100%)`;
}

lengthSlider.addEventListener("input", updateLength);
generateButton.addEventListener("click", () => generatePassword(true));
regenerateButton.addEventListener("click", generatePassword);
copyButton.addEventListener("click", copyPassword);
visibilityButton.addEventListener("click", togglePasswordVisibility);
saveButton.addEventListener("click", savePasswordToVault);
vaultAccessForm.addEventListener("submit", unlockOrCreateVault);
categoryCreateForm.addEventListener("submit", createCategory);
vaultSearchInput.addEventListener("input", renderVaultEntries);
vaultCategoryFilter.addEventListener("change", renderVaultEntries);
vaultLockButton.addEventListener("click", () => {
  lockVault();
  showVaultMessage("Vault locked. Passwords have been cleared from this page.", true);
});

updateLength();
resetStrength();
renderCategoryControls();
updateVaultAccessMode();
try {
  vaultExists = localStorage.getItem(vaultStorageKey) !== null;
  updateVaultAccessMode();
} catch (error) {
  vaultPassphraseInput.disabled = true;
  vaultAccessButton.disabled = true;
  showVaultMessage("Browser storage is unavailable, so the encrypted vault cannot be used.");
  console.error("Unable to access browser storage for password vault:", error);
}
