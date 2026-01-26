import { describe, it, expect } from 'vitest';
import {
  matchesGlobPattern,
  calculateFilePriority,
} from '../src/utils/file-reader.js';

describe('file-reader', () => {
  // ==========================================================================
  // matchesGlobPattern tests
  // ==========================================================================
  describe('matchesGlobPattern', () => {
    describe('root-level file matching', () => {
      it('matches root main.py with **/main.py pattern', () => {
        expect(matchesGlobPattern('main.py', '**/main.py')).toBe(true);
      });

      it('matches root main.py with bare main.py pattern', () => {
        expect(matchesGlobPattern('main.py', 'main.py')).toBe(true);
      });

      it('matches root app.py with **/app.py pattern', () => {
        expect(matchesGlobPattern('app.py', '**/app.py')).toBe(true);
      });

      it('matches root .env with **/.env pattern', () => {
        expect(matchesGlobPattern('.env', '**/.env')).toBe(true);
      });

      it('matches root .env with bare .env pattern', () => {
        expect(matchesGlobPattern('.env', '.env')).toBe(true);
      });
    });

    describe('nested file matching', () => {
      it('matches nested main.py with **/main.py pattern', () => {
        expect(matchesGlobPattern('src/main.py', '**/main.py')).toBe(true);
      });

      it('matches deeply nested main.py with **/main.py pattern', () => {
        expect(matchesGlobPattern('src/core/app/main.py', '**/main.py')).toBe(true);
      });

      it('matches files in agents directory', () => {
        expect(matchesGlobPattern('src/agents/my_agent.py', '**/agents/*.py')).toBe(true);
      });
    });

    describe('wildcard pattern matching', () => {
      it('matches file with agent in name using **/*agent*.py', () => {
        expect(matchesGlobPattern('table_chat_agent.py', '**/*agent*.py')).toBe(true);
      });

      it('matches nested file with agent in name', () => {
        expect(matchesGlobPattern('agent/special/table_chat_agent.py', '**/*agent*.py')).toBe(true);
      });

      it('matches file with exec in name using **/*exec*.py', () => {
        expect(matchesGlobPattern('exec_helper.py', '**/*exec*.py')).toBe(true);
      });

      it('matches file with eval in name using **/*eval*.py', () => {
        expect(matchesGlobPattern('src/eval_utils.py', '**/*eval*.py')).toBe(true);
      });

      it('matches file with generate in name', () => {
        expect(matchesGlobPattern('generate_code_node.py', '**/*generate*.py')).toBe(true);
      });
    });

    describe('directory patterns', () => {
      it('matches files in src directory', () => {
        expect(matchesGlobPattern('src/utils/helper.py', '**/src/**/*.py')).toBe(true);
      });

      it('matches files in core directory', () => {
        expect(matchesGlobPattern('core/engine.py', '**/core/**/*.py')).toBe(true);
      });

      it('matches files in tests directory', () => {
        expect(matchesGlobPattern('tests/unit/test_agent.py', '**/tests/**')).toBe(true);
      });
    });

    describe('case insensitivity', () => {
      it('matches Main.py with **/main.py pattern (case insensitive)', () => {
        expect(matchesGlobPattern('Main.py', '**/main.py')).toBe(true);
      });

      it('matches AGENTS.md with **/agents.md pattern', () => {
        expect(matchesGlobPattern('AGENTS.md', '**/agents.md')).toBe(true);
      });
    });

    describe('negative cases', () => {
      it('does not match unrelated files', () => {
        expect(matchesGlobPattern('readme.txt', '**/main.py')).toBe(false);
      });

      it('does not match partial names without wildcard', () => {
        expect(matchesGlobPattern('main_v2.py', 'main.py')).toBe(false);
      });
    });
  });

  // ==========================================================================
  // calculateFilePriority tests
  // ==========================================================================
  describe('calculateFilePriority', () => {
    describe('CRITICAL priority (1000+)', () => {
      it('assigns critical priority to root main.py', () => {
        const score = calculateFilePriority('main.py');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to root app.py', () => {
        const score = calculateFilePriority('app.py');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to AGENTS.md', () => {
        const score = calculateFilePriority('AGENTS.md');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to .env', () => {
        const score = calculateFilePriority('.env');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to nested main.py', () => {
        const score = calculateFilePriority('src/main.py');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to crew.py', () => {
        const score = calculateFilePriority('crew.py');
        expect(score).toBeGreaterThanOrEqual(1000);
      });

      it('assigns critical priority to graph.py', () => {
        const score = calculateFilePriority('graph.py');
        expect(score).toBeGreaterThanOrEqual(1000);
      });
    });

    describe('HIGH priority (500+)', () => {
      it('assigns high priority to files with agent in name', () => {
        const score = calculateFilePriority('table_chat_agent.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to nested agent files', () => {
        const score = calculateFilePriority('agent/special/table_chat_agent.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to files with exec in name', () => {
        const score = calculateFilePriority('code_exec_helper.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to files with eval in name', () => {
        const score = calculateFilePriority('eval_utils.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to files with sql in name', () => {
        const score = calculateFilePriority('sql_executor.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to files with generate in name', () => {
        const score = calculateFilePriority('generate_code_node.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns high priority to files in src directory', () => {
        const score = calculateFilePriority('src/utils/helper.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });
    });

    describe('MEDIUM priority (100+)', () => {
      it('assigns medium priority to JSON config files', () => {
        const score = calculateFilePriority('some/path/config.json');
        expect(score).toBeGreaterThanOrEqual(100);
      });

      it('assigns medium priority to YAML files', () => {
        const score = calculateFilePriority('workflows/deploy.yaml');
        expect(score).toBeGreaterThanOrEqual(100);
      });
    });

    describe('LOW priority (1-10)', () => {
      it('assigns low priority to test files (but NORMAL matches bump it up)', () => {
        // test_something.py matches:
        // - **/test_*.py (LOW: 1)
        // - **/*.py (NORMAL: 10)
        // Maximum is 10, plus depth bonus 25 = 35
        const score = calculateFilePriority('test_something.py');
        expect(score).toBe(35); // NORMAL (10) + depth bonus (25)
      });

      it('gives HIGH priority to test files containing "agent" in name', () => {
        // tests/unit/test_agent.py matches:
        // - **/tests/** (LOW: 1)
        // - **/*agent*.py (HIGH: 500)
        // This is CORRECT - we want agent files scanned even in tests
        const score = calculateFilePriority('tests/unit/test_agent.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('assigns lower priority to files in examples directory', () => {
        // examples/basic/demo.py matches:
        // - **/examples/** (LOW: 1)
        // - **/*.py (NORMAL: 10)
        // Maximum is 10, no depth bonus (3 levels deep)
        const score = calculateFilePriority('examples/basic/demo.py');
        expect(score).toBe(10);
      });
    });

    describe('maximum score selection', () => {
      it('returns HIGH score for agent file in tests directory (not LOW)', () => {
        // A file like tests/test_agent_helper.py matches both:
        // - **/tests/** (LOW: 1)
        // - **/*agent*.py (HIGH: 500)
        // Should return HIGH (500+)
        const score = calculateFilePriority('tests/test_agent_helper.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('returns HIGH score for src file that is also a test', () => {
        // src/agent_test.py matches:
        // - **/*_test.py (LOW: 1)
        // - **/src/**/*.py (HIGH: 500)
        // - **/*agent*.py (HIGH: 500)
        // Should return HIGH (500+)
        const score = calculateFilePriority('src/agent_test.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });
    });

    describe('depth bonus', () => {
      it('adds depth bonus to shallow files', () => {
        // Root file gets +25 bonus
        const rootScore = calculateFilePriority('random_file.py');
        const deepScore = calculateFilePriority('a/b/c/d/random_file.py');
        expect(rootScore).toBeGreaterThan(deepScore);
      });

      it('adds depth bonus to files one level deep', () => {
        const shallowScore = calculateFilePriority('src/file.py');
        // This should still get bonus (depth <= 2)
        expect(shallowScore).toBeGreaterThan(500); // 500 + 25 bonus
      });
    });

    describe('real-world false negative scenarios', () => {
      // These are the actual files that were missed in testing

      it('prioritizes langroid table_chat_agent.py correctly', () => {
        // This file contains eval() but was being missed
        // Path: langroid/agent/special/table_chat_agent.py
        const score = calculateFilePriority('langroid/agent/special/table_chat_agent.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('prioritizes Scrapegraph-ai generate_code_node.py correctly', () => {
        // This file contains exec() but was being missed
        // Path: scrapegraphai/nodes/generate_code_node.py
        const score = calculateFilePriority('scrapegraphai/nodes/generate_code_node.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });

      it('prioritizes gpt-researcher files in src correctly', () => {
        // Files in src/ directory should get HIGH priority
        const score = calculateFilePriority('gpt_researcher/agent/research_agent.py');
        expect(score).toBeGreaterThanOrEqual(500);
      });
    });

    describe('default score for unmatched files', () => {
      it('assigns default score to random unmatched files', () => {
        const score = calculateFilePriority('deeply/nested/path/to/obscure_file.xyz');
        expect(score).toBe(5);
      });
    });
  });

  // ==========================================================================
  // Integration: Priority ordering tests
  // ==========================================================================
  describe('priority ordering', () => {
    it('orders files correctly: critical > high > medium > normal', () => {
      const files = [
        'deep/nested/path/test_something.py', // NORMAL (10), no depth bonus
        'random.py', // NORMAL (10) + depth bonus (25) = 35
        'some/config.json', // MEDIUM (100)
        'table_chat_agent.py', // HIGH (500) + depth bonus (25) = 525
        'main.py', // CRITICAL (1000) + depth bonus (25) = 1025
      ];

      const scored = files
        .map((f) => ({ path: f, score: calculateFilePriority(f) }))
        .sort((a, b) => b.score - a.score);

      // main.py should be first (CRITICAL + depth bonus)
      expect(scored[0].path).toBe('main.py');
      // table_chat_agent.py should be second (HIGH + depth bonus)
      expect(scored[1].path).toBe('table_chat_agent.py');
      // config.json should be third (MEDIUM)
      expect(scored[2].path).toBe('some/config.json');
      // random.py should be fourth (NORMAL + depth bonus)
      expect(scored[3].path).toBe('random.py');
      // deep test file should be last (NORMAL, no depth bonus)
      expect(scored[4].path).toBe('deep/nested/path/test_something.py');
    });

    it('ensures agent files are scanned before test files in same directory', () => {
      const files = [
        'tests/test_utils.py',
        'tests/agent_helper.py', // Contains "agent" - should be HIGH
      ];

      const scored = files
        .map((f) => ({ path: f, score: calculateFilePriority(f) }))
        .sort((a, b) => b.score - a.score);

      expect(scored[0].path).toBe('tests/agent_helper.py');
      expect(scored[1].path).toBe('tests/test_utils.py');
    });
  });
});
