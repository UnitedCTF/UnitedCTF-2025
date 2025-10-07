import Alpine from "alpinejs";
import dayjs from "dayjs";

import CTFd from "./index";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";

import { Modal, Tab, Tooltip } from "bootstrap";
import highlight from "./theme/highlight";
import { GeoJSONLoader } from 'three-geojson';
import { WGS84_ELLIPSOID } from '3d-tiles-renderer';

function addTargetBlank(html) {
  let dom = new DOMParser();
  let view = dom.parseFromString(html, "text/html");
  let links = view.querySelectorAll('a[href*="://"]');
  links.forEach(link => {
    link.setAttribute("target", "_blank");
  });
  return view.documentElement.outerHTML;
}

window.Alpine = Alpine;

Alpine.store("challenge", {
  data: {
    view: "",
  },
});

Alpine.data("Hint", () => ({
  id: null,
  html: null,

  async showHint(event) {
    if (event.target.open) {
      let response = await CTFd.pages.challenge.loadHint(this.id);

      // Hint has some kind of prerequisite or access prevention
      if (response.errors) {
        event.target.open = false;
        CTFd._functions.challenge.displayUnlockError(response);
        return;
      }
      let hint = response.data;
      if (hint.content) {
        this.html = addTargetBlank(hint.html);
      } else {
        let answer = await CTFd.pages.challenge.displayUnlock(this.id);
        if (answer) {
          let unlock = await CTFd.pages.challenge.loadUnlock(this.id);

          if (unlock.success) {
            let response = await CTFd.pages.challenge.loadHint(this.id);
            let hint = response.data;
            this.html = addTargetBlank(hint.html);
          } else {
            event.target.open = false;
            CTFd._functions.challenge.displayUnlockError(unlock);
          }
        } else {
          event.target.open = false;
        }
      }
    }
  },
}));

Alpine.data("Challenge", () => ({
  id: null,
  next_id: null,
  submission: "",
  tab: null,
  solves: [],
  submissions: [],
  solution: null,
  response: null,
  share_url: null,
  max_attempts: 0,
  attempts: 0,
  cfss: '',
  author: '',
  position: '',

  async init() {
    highlight();
  },

  getStyles() {
    let styles = {
      "modal-dialog": true,
    };
    try {
      let size = CTFd.config.themeSettings.challenge_window_size;
      switch (size) {
        case "sm":
          styles["modal-sm"] = true;
          break;
        case "lg":
          styles["modal-lg"] = true;
          break;
        case "xl":
          styles["modal-xl"] = true;
          break;
        default:
          break;
      }
    } catch (error) {
      // Ignore errors with challenge window size
      console.log("Error processing challenge_window_size");
      console.log(error);
    }
    return styles;
  },

  async init() {
    highlight();
  },

  async showChallenge() {
    new Tab(this.$el).show();
  },

  async showSolves() {
    this.solves = await CTFd.pages.challenge.loadSolves(this.id);
    this.solves.forEach(solve => {
      solve.date = dayjs(solve.date).format("MMMM Do, h:mm:ss A");
      return solve;
    });
    new Tab(this.$el).show();
  },

  async showSubmissions() {
    let response = await CTFd.pages.users.userSubmissions("me", this.id);
    this.submissions = response.data;
    this.submissions.forEach(s => {
      s.date = dayjs(s.date).format("MMMM Do, h:mm:ss A");
      return s;
    });
    new Tab(this.$el).show();
  },

  getSolutionId() {
    let data = Alpine.store("challenge").data;
    return data.solution_id;
  },

  async showSolution() {
    let solution_id = this.getSolutionId();
    CTFd._functions.challenge.displaySolution = solution => {
      this.solution = solution.html;
      new Tab(this.$el).show();
    };
    await CTFd.pages.challenge.displaySolution(solution_id);
  },

  getNextId() {
    let data = Alpine.store("challenge").data;
    return data.next_id;
  },

  async nextChallenge() {
    let modal = Modal.getOrCreateInstance("[x-ref='challengeWindow']");

    // TODO: Get rid of this private attribute access
    // See https://github.com/twbs/bootstrap/issues/31266
    modal._element.addEventListener(
      "hidden.bs.modal",
      event => {
        // Dispatch load-challenge event to call loadChallenge in the ChallengeBoard
        Alpine.nextTick(() => {
          this.$dispatch("load-challenge", this.getNextId());
        });
      },
      { once: true },
    );
    modal.hide();
  },

  async getShareUrl() {
    let body = {
      type: "solve",
      challenge_id: this.id,
    };
    const response = await CTFd.fetch("/api/v1/shares", {
      method: "POST",
      body: JSON.stringify(body),
    });
    const data = await response.json();
    const url = data["data"]["url"];
    this.share_url = url;
  },

  copyShareUrl() {
    navigator.clipboard.writeText(this.share_url);
    let t = Tooltip.getOrCreateInstance(this.$el);
    t.enable();
    t.show();
    setTimeout(() => {
      t.hide();
      t.disable();
    }, 2000);
  },

  async submitChallenge() {
    this.response = await CTFd.pages.challenge.submitChallenge(
      this.id,
      this.submission,
    );

    await this.renderSubmissionResponse();
  },

  async renderSubmissionResponse() {
    if (this.response.data.status === "correct") {
      this.submission = "";
    }

    // Increment attempts counter
    if (
      this.max_attempts > 0 &&
      this.response.data.status != "already_solved" &&
      this.response.data.status != "ratelimited"
    ) {
      this.attempts += 1;
    }

    // Dispatch load-challenges event to call loadChallenges in the ChallengeBoard
    this.$dispatch("load-challenges");
  },
}));

Alpine.store("challengeBoard", {
  challenges: [],
  challengesTree: {},
});

Alpine.data("ChallengeBoard", () => ({
  loaded: false,
  challenges: [],
  challenge: null,
  challengesTree: {},

  async init() {
    const chals = [];
    const resp = await CTFd.pages.challenges.getChallenges();
    const tree = Object.entries(
      resp.reduce((acc, chal) => {
        const {
          id,
          name,
          category,
          solved_by_me: completed,
          value: score,
          tags
        } = chal;

        const author = tags.find(t => t.value.startsWith("A:"))?.value.slice(2) || "???";
        const cfssScore = tags.find(t => t.value.startsWith("CFSS:"))?.value.slice(5);
        const position = tags.find(t => t.value.startsWith("V:"))?.value.slice(2);
        const tabid = tags.find(t => t.value.startsWith("TI:"))?.value.slice(3);

        if (!acc[category]) acc[category] = { chals: [], tabs: {} };
        if (tabid && !acc[category].tabs[tabid])
          acc[category].tabs[tabid] = [];

        let entry = { id, name, category, completed, score, author, cfssScore, position };
        chals.push(entry);

        if (tabid)
          acc[category].tabs[tabid].push(entry);
        else
          acc[category].chals.push(entry);

        return acc;
      }, {})).reduce((acc1, [category, data]) => {
        const els = [...data.chals, ...Object.values(data.tabs)]
          .map(item => ({ ...item }))
          .sort((a, b) => {
            let as = Array.isArray(a?.score) ? a.score[0] : a?.score ?? 0;
            let bs = Array.isArray(b?.score) ? b.score[0] : b?.score ?? 0;
            return as - bs;
          }).flat();
        acc1[category] = Object.freeze(els);

        return acc1;
      }, {});


    this.challenges = chals;
    window.dispatchEvent(new CustomEvent('challenges-loaded', { detail: chals }));

    this.loaded = true;

    Alpine.store('challengeBoard').challenges = this.challenges;
    Alpine.store('challengeBoard').challengesTree = Object.freeze(tree);

    if (window.location.hash) {
      let chalHash = decodeURIComponent(window.location.hash.substring(1));
      let idx = chalHash.lastIndexOf("-");
      if (idx >= 0) {
        let pieces = [chalHash.slice(0, idx), chalHash.slice(idx + 1)];
        let id = pieces[1];
        await this.loadChallenge(id);
      }
    }
  },

  getCategories() {
    const categories = [];

    this.challenges.forEach(challenge => {
      const { category } = challenge;

      if (!categories.includes(category)) {
        categories.push(category);
      }
    });

    try {
      const f = CTFd.config.themeSettings.challenge_category_order;
      if (f) {
        const getSort = new Function(`return (${f})`);
        categories.sort(getSort());
      }
    } catch (error) {
      // Ignore errors with theme category sorting
      console.log("Error running challenge_category_order function");
      console.log(error);
    }

    return categories;
  },

  getChallenges(category) {
    let challenges = this.challenges;

    if (category !== null) {
      challenges = this.challenges.filter(challenge => challenge.category === category);
    }

    try {
      const f = CTFd.config.themeSettings.challenge_order;
      if (f) {
        const getSort = new Function(`return (${f})`);
        challenges.sort(getSort());
      }
    } catch (error) {
      // Ignore errors with theme challenge sorting
      console.log("Error running challenge_order function");
      console.log(error);
    }

    return challenges;
  },

  async loadChallenges() {
    const chals = [];
    this.challenges = await CTFd.pages.challenges.getChallenges();
    const tree = Object.entries(
      this.challenges.reduce((acc, chal) => {
        const {
          id,
          name,
          category,
          solved_by_me: completed,
          value: score,
          tags
        } = chal;

        const author = tags.find(t => t.value.startsWith("A:"))?.value.slice(2) || "???";
        const cfssScore = tags.find(t => t.value.startsWith("CFSS:"))?.value.slice(5);
        const position = tags.find(t => t.value.startsWith("V:"))?.value.slice(2);
        const tabid = tags.find(t => t.value.startsWith("TI:"))?.value.slice(3);

        if (!acc[category]) acc[category] = { chals: [], tabs: {} };
        if (tabid && !acc[category].tabs[tabid])
          acc[category].tabs[tabid] = [];

        let entry = { id, name, category, completed, score, author, cfssScore, position };
        chals.push(entry);

        if (tabid)
          acc[category].tabs[tabid].push(entry);
        else
          acc[category].chals.push(entry);

        return acc;
      }, {})).reduce((acc1, [category, data]) => {
        const els = [...data.chals, ...Object.values(data.tabs)]
          .map(item => ({ ...item }))
          .sort((a, b) => {
            let as = Array.isArray(a?.score) ? a.score[0] : a?.score ?? 0;
            let bs = Array.isArray(b?.score) ? b.score[0] : b?.score ?? 0;
            return as - bs;
          }).flat();
        acc1[category] = Object.freeze(els);

        return acc1;
      }, {});

    Alpine.store('challengeBoard').challenges = this.challenges;
    Alpine.store('challengeBoard').challengesTree = Object.freeze(tree);
  },

  async loadChallenge(challengeId) {
    await CTFd.pages.challenge.displayChallenge(challengeId, challenge => {
      challenge.data.view = addTargetBlank(challenge.data.view);
     
      Alpine.store("challenge").data = challenge.data;

      // nextTick is required here because we're working in a callback
      Alpine.nextTick(() => {
        let modal = Modal.getOrCreateInstance("[x-ref='challengeWindow']");
        console.log("modal", modal);
        // TODO: Get rid of this private attribute access
        // See https://github.com/twbs/bootstrap/issues/31266
        modal._element.addEventListener(
          "hidden.bs.modal",
          event => {
            // Remove location hash
            history.replaceState(null, null, " ");
          },
          { once: true },
        );
        modal.show();
        history.replaceState(null, null, `#${challenge.data.name}-${challengeId}`);
      });
    });
  },
}));

Alpine.data('fuzzyFinder', () => ({
  chals: [],
  chalsTree: {},
  query: '',
  suggestions: [],
  selectedIdx: -1,
  showSuggestions: false,
  collapsedCategories: {},


  init() {
    this.chals = Alpine.store('challengeBoard').challenges;
    this.chalsTree = Alpine.store('challengeBoard').challengesTree;
    this.$watch('$store.challengeBoard.challenges', (challenges) => {
      this.chals = challenges;
    });
    this.$watch('$store.challengeBoard.challengesTree', (tree) => {
      this.chalsTree = tree;
    });
  },

  handleInput() {
    this.generateSuggestions();
    this.showSuggestions = true;
    this.selectedIdx = -1;
  },

  handleFocus() {
    if (this.suggestions.length > 0) {
      this.showSuggestions = true;
    }
  },

  handleBlur() {
    setTimeout(() => {
      this.showSuggestions = false;
    }, 200);
  },

  handleKeydown(e) {
    if (!this.showSuggestions || this.suggestions.length === 0) return;
    const el = this.$refs.fuzzyContainer;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        this.selectedIdx = Math.min(this.selectedIdx + 1, this.suggestions.length - 1);
        if (this.selectedIdx !== -1)
          el.scrollTo(0, (this.selectedIdx + 1) * el.querySelector('.suggestion-item').offsetHeight - el.clientHeight);
        break;
      case 'ArrowUp':
        e.preventDefault();
        this.selectedIdx = Math.max(this.selectedIdx - 1, -1);
        if (this.selectedIdx !== -1)
          el.scrollTo(0, (this.selectedIdx + 1) * el.querySelector('.suggestion-item').offsetHeight - el.clientHeight);
        break;
      case 'Enter':
        e.preventDefault();
        if (this.selectedIdx >= 0) {
          this.selectSuggestion(this.suggestions[this.selectedIdx]);
        }
        break;
      case 'Escape':
        this.showSuggestions = false;
        this.selectedIdx = -1;
        break;
    }
  },

  generateSuggestions() {
    const q = this.query.toLowerCase();
    if (!q) {
      this.suggestions = [];
      return;
    }

    const chalSuggestions = this.chals
      .filter(t => t.name.toLowerCase().includes(q))
      .map(t => ({ text: t.name, type: 'chal', name: 'défi' }));

    const authorSuggestions = [...new Set(this.chals.map(t => t.author))]
      .filter(t => t.toLowerCase().includes(q))
      .map(t => ({ text: t, type: 'author', name: 'auteur' }));

    const categorySuggestions = [...new Set(this.chals.map(t => t.category))]
      .filter(t => t.toLowerCase().includes(q))
      .map(t => ({ text: t, type: 'category', name: 'catégorie' }));

    this.suggestions = [...chalSuggestions, ...authorSuggestions, ...categorySuggestions]
      .sort((a, b) => a.text.localeCompare(b.text));
  },

  selectSuggestion(suggestion) {
    this.query = suggestion.text;
    this.showSuggestions = false;
    this.selectedIdx = -1;
  },

  getFilteredChals() {
    const q = this.query.toLowerCase();
    return this.chals.filter(chal => {
      return (
        !this.query ||
        chal.name.toLowerCase().includes(q) ||
        chal.author.toLowerCase().includes(q) ||
        chal.category.toLowerCase().includes(q)
      );
    });
  },

  getChalTree() {
    const q = this.query.toLowerCase();
    const isFiltered = (chal) =>
      !this.query ||
      chal.name.toLowerCase().includes(q) ||
      chal.author.toLowerCase().includes(q) ||
      chal.category.toLowerCase().includes(q);

    const tree = {};
    Object.entries(this.chalsTree).forEach(([category, chals]) => {
      const filtered = chals.filter(isFiltered);
      if (filtered.length > 0)
        tree[category] = filtered;

    });

    return tree;
  },

  toggleCategory(category) {
    this.collapsedCategories[category] = !this.collapsedCategories[category];
  },

  getScoreLevel(score) {
    if (score == 1) return 'intro';
    if (score <= 3) return 'easy';
    if (score <= 6) return 'medium';
    if (score <= 9) return 'hard';
    return 'oulala';
  },
}));



Alpine.start();
