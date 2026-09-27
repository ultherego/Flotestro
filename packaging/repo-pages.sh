#!/usr/bin/env bash
# Writes the pages a person sees when they open the repository in a browser.
#
#   repo-pages.sh <repo-dir> <base-url>
#
# GitHub Pages serves no directory index, so the addresses a host installs from
# - <base>/deb, <base>/rpm, <base>/arch - answered 404 to a browser while apt,
# dnf and pacman were reading them happily. Somebody who opened the link the
# README gives concluded the repository was empty. Each tree gets a page of its
# own here: what it is, the lines that add it, the key that signs it, and the
# packages it actually carries, read out of the tree rather than restated.
#
# The pages are ordinary files of the published tree, so they travel into the
# package-repository image an isolated site serves as well.
set -euo pipefail

REPO="${1:?give the repository directory}"
BASE="${2:?give the URL the repository is served at}"
BASE="${BASE%/}"
SITE="${BASE%/packages}"
[ -d "$REPO" ] || { echo "$REPO is not a directory" >&2; exit 1; }

# packageRows prints a table row per package name with the versions of it the
# tree carries, read from the file names. Each family writes a name
# differently, so each is split by its own rule rather than by a guess that
# happens to work for two of them.
#
#   deb    flotestro-agent_0.61.0_amd64.deb
#   rpm    flotestro-agent-0.61.0-1.x86_64.rpm
#   arch   flotestro-agent-0.61.0-1-x86_64.pkg.tar.zst
packageRows() {
    local family="$1" pattern="$2"
    find "$REPO/$family" -name "$pattern" -type f 2>/dev/null |
    awk -v family="$family" '
        { file = $0; sub(/^.*\//, "", file) }
        family == "deb" {
            n = split(file, part, "_"); print part[1] "\t" part[2]; next
        }
        {
            # Strip the extension, then take the trailing fields off: release
            # and architecture for rpm, release and architecture as separate
            # "-" fields for pacman. What is left is the name.
            if (family == "rpm") { sub(/\.rpm$/, "", file); sub(/\.[^.]+$/, "", file); drop = 2 }
            else                 { sub(/\.pkg\.tar\..*$/, "", file); drop = 3 }
            n = split(file, part, "-")
            if (n <= drop) next
            name = part[1]
            for (i = 2; i <= n - drop; i++) name = name "-" part[i]
            print name "\t" part[n - drop + 1]
        }' |
    sort -u -t$'\t' -k1,1 -k2,2V |
    awk -F'\t' '
        { if ($1 != name) { if (name != "") print name "\t" versions; name = $1; versions = $2 }
          else            { versions = versions ", " $2 } }
        END { if (name != "") print name "\t" versions }' |
    while IFS=$'\t' read -r name versions; do
        printf '        <tr><td><code>%s</code></td><td>%s</td></tr>\n' "$name" "$versions"
    done
}

# historyNote explains the packages of the panel and the relay, and only for a
# tree that still carries some. A repository composed after 0.62.0 has none and
# the paragraph would be a puzzle rather than an explanation.
historyNote() {
    local family="$1"; shift
    local -a match=()
    local pattern
    for pattern in "$@"; do
        [ ${#match[@]} -eq 0 ] || match+=(-o)
        match+=(-name "$pattern")
    done
    find "$REPO/$family" -type f \( "${match[@]}" \) 2>/dev/null |
        grep -qE '/flotestro-(control-plane|relay)[-_]' || return 0
    cat <<'HTML'

    <p>Versions of <code>flotestro-control-plane</code> and
    <code>flotestro-relay</code> published before 0.62.0 are still in this tree.
    A published file is never withdrawn, so a host that has not moved yet still
    finds what it is running; they are history and not a way to install either.
    Both are deployed from their images now.</p>
HTML
}

# fileLink names a file of the tree: a link when it is there, the name alone
# when it is not. The pages point at the stable channel because that is what the
# commands on them use, and a repository that carries only a pre-release has no
# such file to link to.
fileLink() {
    local relative="$1" label="$2" from="$3"
    if [ -e "$REPO/$from/$relative" ]; then
        printf '<a href="%s"><code>%s</code></a>' "$relative" "$label"
    else
        printf '<code>%s</code>' "$label"
    fi
}

# carries is the same two paragraphs on every page: what is here and what is
# deliberately not.
carries() {
    cat <<HTML
    <p>One package, <code>flotestro-agent</code>, carrying the three binaries a
    managed host runs: the agent, the root helper
    <code>flotestro-agent-helper</code> it asks for the operations that need
    privileges, and <code>flotestro-agentctl</code>, which enrolls the host and
    answers questions about it locally. The agent is a native package because it
    manages the host itself - its PID 1, its devices, its package database.</p>

    <p>The panel and the relay are not here. They are published as OCI images,
    <code>ghcr.io/ultherego/flotestro-control-plane</code> and
    <code>ghcr.io/ultherego/flotestro-relay</code>, and deployed with Compose;
    <a href="$SITE/docs/installation.html">Installation</a> is the procedure.</p>
HTML
}

# page wraps a body read from standard input in the same shell as the rest of
# the site. The stylesheet lies at the root of the published site; a tree served
# on its own - the package-repository image of an isolated site - has none, and
# the page is then plain HTML in the right order, which still reads.
page() {
    local path="$1" title="$2" description="$3" up="$4"
    mkdir -p "$(dirname "$REPO/$path")"
    {
        cat <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<meta name="description" content="$description">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;600&display=swap">
<link rel="stylesheet" href="$up/style.css">
</head>
<body>

<header class="site-header">
  <div class="site-header__inner">
    <a class="brand" href="$SITE/">Flotestro</a>
    <nav class="site-nav">
      <a href="$SITE/">Overview</a>
      <a href="$SITE/docs/">Documentation</a>
      <a href="$BASE/" aria-current="page">Packages</a>
      <a href="https://github.com/ultherego/Flotestro">Source</a>
    </nav>
  </div>
</header>

<div class="layout layout--plain">
  <main class="content">
HTML
        cat
        cat <<HTML
  </main>
</div>

<footer class="site-footer">
  <div class="site-footer__inner">
    <p>Every index here is signed with <a href="$BASE/flotestro-repo.asc">flotestro-repo.asc</a>.</p>
    <p><a href="https://github.com/ultherego/Flotestro">github.com/ultherego/Flotestro</a></p>
  </div>
</footer>

</body>
</html>
HTML
    } > "$REPO/$path"
}

# --- the root -----------------------------------------------------------
{
    cat <<HTML
    <h1>Flotestro packages</h1>

    <p class="lede">The signed repository the hosts of a Flotestro fleet install
    their agent from. Three trees, one per package manager, carrying the same
    package and signed with the same key.</p>

    <ul class="cards">
      <li class="card">
        <p class="card__title"><a href="deb/">apt</a></p>
        <p>Debian, Ubuntu and their derivatives. A flat repository under
        <code>deb/</code>, one suite per channel.</p>
      </li>
      <li class="card">
        <p class="card__title"><a href="rpm/">dnf</a></p>
        <p>Fedora, RHEL and what follows them. One <code>createrepo_c</code> tree
        per channel under <code>rpm/</code>.</p>
      </li>
      <li class="card">
        <p class="card__title"><a href="arch/">pacman</a></p>
        <p>Arch Linux. One <code>flotestro.db</code> per channel and architecture
        under <code>arch/</code>.</p>
      </li>
    </ul>

    <h2>What it carries</h2>
HTML
    carries
    historyNote "" '*.deb' '*.rpm' '*.pkg.tar.zst'
    cat <<HTML

    <h2>The key</h2>

    <p>Every index in every tree is signed, and the public half of the key that
    signs them is <a href="flotestro-repo.asc"><code>flotestro-repo.asc</code></a>.
    A host imports it before it installs anything. HTTPS says who served a file
    and the signature says who built it, and for a package that will run as root
    on every machine in a fleet the second question is the one that matters.</p>

    <p>The panel writes the whole command for a host under <strong>Add host</strong>,
    with the channel and the address of this repository already in it. The three
    pages above are the same lines, for reading and for a host the panel has not
    been told about yet.</p>

    <h2>Channels</h2>

    <p>A channel is a suite for apt, a directory for dnf and pacman, and a word in
    the command a host is given. <code>stable</code> is a finished release. A
    pre-release goes to a channel of its own that a host asking for
    <code>stable</code> never reads, and it is not moved into <code>stable</code>
    afterwards: the version that was tested is the version that is published.</p>

    <p>A published file is never replaced. Each release adds to the trees and every
    index is composed again over all of them, so a host on an older version keeps
    finding the version it runs and a rollback has something to roll back to.</p>

    <h2>What is beside the repository</h2>

    <p><code>releases/&lt;version&gt;/</code> holds the manifests of one release -
    <code>SHA256SUMS</code>, its signature, and the provenance statement naming
    the run that built it. Those cover the release as it was built; the
    <code>.rpm</code> files in the tree carry a signature of their own that the
    loose files do not, and <code>rpm --checksig</code> is what answers for
    them.</p>
HTML
} | page "index.html" "Flotestro packages" \
    "The signed apt, dnf and pacman repository the hosts of a Flotestro fleet install their agent from." \
    ".."

# --- apt ----------------------------------------------------------------
if [ -d "$REPO/deb" ]; then
    {
        cat <<HTML
    <h1>Flotestro for apt</h1>

    <p class="lede">The <code>.deb</code> tree of the
    <a href="../">Flotestro package repository</a>, for Debian, Ubuntu and their
    derivatives. There is no directory listing to browse; this page is what the
    tree holds and how to add it.</p>

    <h2>Adding it</h2>

    <p class="filename">On the host, as an administrator</p>
<pre><code>sudo install -d -m 0755 /etc/apt/keyrings
curl -fsS $BASE/flotestro-repo.asc | sudo tee /etc/apt/keyrings/flotestro.asc &gt;/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/flotestro.asc] $BASE/deb stable main' | sudo tee /etc/apt/sources.list.d/flotestro.list &gt;/dev/null
sudo apt-get update
sudo apt-get install -y flotestro-agent</code></pre>

    <p><code>signed-by</code> binds the key to this one source, so the key that
    signs Flotestro cannot vouch for anything else on the host. Put another
    channel in place of <code>stable</code> to follow that one instead.</p>

    <h2>What it carries</h2>
HTML
        carries
        cat <<'HTML'

    <div class="table-scroll">
    <table>
      <thead><tr><th>Package</th><th>Versions in the tree</th></tr></thead>
      <tbody>
HTML
        packageRows deb '*.deb'
        cat <<'HTML'
      </tbody>
    </table>
    </div>
HTML
        historyNote deb '*.deb'
        cat <<HTML

    <h2>The layout</h2>

    <p>A flat repository with one component: the fleet has one package source,
    not a distribution tree.
    <code>dists/&lt;channel&gt;/main/binary-amd64</code> and
    <code>binary-arm64</code> hold the index and
    <code>pool/&lt;channel&gt;</code> the files. The index lists every version the
    channel has carried rather than the newest alone, so an older one can still be
    asked for by name; apt takes the highest by itself.</p>

    <h2>What proves where a package came from</h2>

    <p>The repository index, not the file. Debian's trust model does not sign
    individual packages - <code>dpkg-sig</code> and <code>debsig-verify</code>
    exist, no distribution enables them and <code>apt</code> never consults them -
    so a signature on the <code>.deb</code> would prove nothing to the host that
    installs it. What binds the bytes here is a chain:
    $(fileLink dists/stable/InRelease InRelease deb) is signed and
    carries the checksum of <code>Packages</code>, and <code>Packages</code>
    carries the checksum of every <code>.deb</code>.</p>

    <p>So an agent upgrade planned for a host of this family names no signing key,
    and a plan that names one is refused with
    <code class="refusal">agent_package_signer_not_applicable</code> before it is
    sent. What the host reports instead is what it can establish: the address the
    file came from, the release file of that repository, and the key
    <code>gpgv</code> accepted the signature of the index on.</p>
HTML
    } | page "deb/index.html" "Flotestro for apt" \
        "The Debian and Ubuntu tree of the signed Flotestro package repository: the lines that add it and the packages it carries." \
        "../.."
fi

# --- dnf ----------------------------------------------------------------
if [ -d "$REPO/rpm" ]; then
    {
        cat <<HTML
    <h1>Flotestro for dnf</h1>

    <p class="lede">The <code>.rpm</code> tree of the
    <a href="../">Flotestro package repository</a>, for Fedora, RHEL and what
    follows them. There is no directory listing to browse; this page is what the
    tree holds and how to add it.</p>

    <h2>Adding it</h2>

    <p class="filename">On the host, as an administrator</p>
<pre><code>sudo rpm --import $BASE/flotestro-repo.asc
printf '%s\n' '[flotestro]' 'name=Flotestro' 'baseurl=$BASE/rpm/stable' \\
  'enabled=1' 'gpgcheck=1' 'repo_gpgcheck=1' 'gpgkey=$BASE/flotestro-repo.asc' \\
  | sudo tee /etc/yum.repos.d/flotestro.repo &gt;/dev/null
sudo dnf install -y flotestro-agent</code></pre>

    <p><code>gpgcheck</code> is the signature on the package and
    <code>repo_gpgcheck</code> the one on the metadata; both are on. The first
    protects the file and the second the list of files, and a repository checked
    only the first way could still offer a different version of a package that
    verifies. Put another channel in the <code>baseurl</code> in place of
    <code>stable</code> to follow that one instead.</p>

    <h2>What it carries</h2>
HTML
        carries
        cat <<'HTML'

    <div class="table-scroll">
    <table>
      <thead><tr><th>Package</th><th>Versions in the tree</th></tr></thead>
      <tbody>
HTML
        packageRows rpm '*.rpm'
        cat <<'HTML'
      </tbody>
    </table>
    </div>
HTML
        historyNote rpm '*.rpm'
        cat <<HTML

    <h2>The layout</h2>

    <p>One <code>createrepo_c</code> tree per channel,
    <code>rpm/&lt;channel&gt;</code>, with the metadata under
    <code>repodata/</code> and
    $(fileLink stable/repodata/repomd.xml repomd.xml rpm) signed beside
    itself as <code>repomd.xml.asc</code>. The metadata is composed over the whole
    directory, so the index offers every version the channel has carried and dnf
    takes the highest.</p>

    <h2>What proves where a package came from</h2>

    <p>The package file itself. The signature is in its header, written by
    <code>rpmsign</code> with the release key, and <code>rpm --checksig</code>
    names the key that made it. An agent upgrade on a host of this family may
    therefore demand a particular signing key, and a package signed by anything
    else is refused before it is installed.</p>
HTML
    } | page "rpm/index.html" "Flotestro for dnf" \
        "The Fedora and RHEL tree of the signed Flotestro package repository: the lines that add it and the packages it carries." \
        "../.."
fi

# --- pacman -------------------------------------------------------------
if [ -d "$REPO/arch" ]; then
    {
        cat <<HTML
    <h1>Flotestro for pacman</h1>

    <p class="lede">The pacman tree of the
    <a href="../">Flotestro package repository</a>, for Arch Linux. There is no
    directory listing to browse; this page is what the tree holds and how to add
    it.</p>

    <h2>Adding it</h2>

    <p class="filename">On the host, as an administrator</p>
<pre><code>curl -fsS $BASE/flotestro-repo.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key "\$(curl -fsS $BASE/flotestro-repo.asc | gpg --show-keys --with-colons | awk -F: '/^fpr:/ {print \$10; exit}')"
printf '%s\n' '[flotestro]' 'SigLevel = Required DatabaseRequired' 'Server = $BASE/arch/stable' | sudo tee -a /etc/pacman.conf &gt;/dev/null
sudo pacman -Sy
sudo pacman -S --noconfirm flotestro-agent</code></pre>

    <p>The key is signed locally after it is added, or pacman holds it without
    trusting it and refuses every package. <code>SigLevel = Required
    DatabaseRequired</code> is the point of the exercise: the package and the
    database must both carry a signature this host accepts. Put another channel in
    the <code>Server</code> line in place of <code>stable</code> to follow that one
    instead.</p>

    <h2>What it carries</h2>
HTML
        carries
        cat <<'HTML'

    <div class="table-scroll">
    <table>
      <thead><tr><th>Package</th><th>Versions in the tree</th></tr></thead>
      <tbody>
HTML
        packageRows arch '*.pkg.tar.zst'
        cat <<'HTML'
      </tbody>
    </table>
    </div>
HTML
        historyNote arch '*.pkg.tar.zst'
        cat <<HTML

    <h2>The layout</h2>

    <p>One database per channel and architecture. pacman reads a single
    <code>&lt;Server&gt;/flotestro.db</code>, and an entry for a foreign
    architecture in it is an entry every host refuses - so <code>x86_64</code>,
    the architecture Arch Linux itself has, stands at
    <code>arch/&lt;channel&gt;</code> where the command above points, and any
    other one gets a directory of its own beside it.</p>

    <h2>What proves where a package came from</h2>

    <p>The package file itself, with a detached <code>.sig</code> beside it, and
    the $(fileLink stable/flotestro.db flotestro.db arch) with one of its own.
    <code>gpg</code> against pacman's keyring names the key that made the
    signature, so an agent upgrade on a host of this family may demand a
    particular one.</p>
HTML
    } | page "arch/index.html" "Flotestro for pacman" \
        "The Arch Linux tree of the signed Flotestro package repository: the lines that add it and the packages it carries." \
        "../.."
fi

echo "==> repository pages written under $REPO"
