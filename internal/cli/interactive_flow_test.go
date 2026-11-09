package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// A command that changes the host asks first, and only an explicit yes goes on.
type interactiveCommand struct {
	name string
	// prepare builds the host and returns the arguments (without -yes).
	prepare func(t *testing.T) []string
	run     func(ctx context.Context, out io.Writer, args []string) error
	asked   string
}

func interactiveCommands() []interactiveCommand {
	history := func(t *testing.T) []string { _, args := twoGenerations(t); return args }
	return []interactiveCommand{
		{"apply", plannedHost, runBootstrapApply, "Apply this plan"},
		{"rollback", history, runBootstrapRollback, "Apply this rollback"},
		{"rotate", func(t *testing.T) []string { return append(history(t), "-users", "owner") }, runBootstrapRotate, "Reissue these credentials"},
	}
}

func TestInteractiveCommandsActOnlyOnAnExplicitYes(t *testing.T) {
	for _, command := range interactiveCommands() {
		for answer, wantRuns := range map[string]int{"yes\n": 1, "no\n": 0, "y\n": 0, "\n": 0} {
			stub := &engineStub{result: okResult()}
			stubEngine(t, stub)
			args := command.prepare(t)
			atTerminal(t, "")
			stdinHolds(t, answer)

			var out bytes.Buffer
			if err := command.run(context.Background(), &out, args); err != nil {
				t.Fatalf("%s %q: %v\n%s", command.name, answer, err, out.String())
			}
			if stub.runCalls != wantRuns {
				t.Errorf("%s %q: engine runs = %d, want %d", command.name, answer, stub.runCalls, wantRuns)
			}
			if !strings.Contains(out.String(), command.asked) {
				t.Errorf("%s %q: the question was not asked:\n%s", command.name, answer, out.String())
			}
			if wantRuns == 0 && !strings.Contains(out.String(), "nothing was changed") {
				t.Errorf("%s %q: a refusal did not say so:\n%s", command.name, answer, out.String())
			}
		}
	}
}

func TestInteractiveCommandsTreatAClosedInputAsNoConsent(t *testing.T) {
	for _, command := range interactiveCommands() {
		stub := &engineStub{result: okResult()}
		stubEngine(t, stub)
		args := command.prepare(t)
		atTerminal(t, "")
		stdinHolds(t, "")
		if err := command.run(context.Background(), &bytes.Buffer{}, args); err == nil {
			t.Errorf("%s: end of input was taken as consent", command.name)
		}
		if stub.runCalls != 0 {
			t.Errorf("%s: the engine ran without an answer", command.name)
		}
	}
}

func TestInteractiveCommandsRefuseWhenThereIsNobodyToAsk(t *testing.T) {
	for _, command := range interactiveCommands() {
		stub := &engineStub{result: okResult()}
		stubEngine(t, stub)
		args := command.prepare(t)
		old := promptIsTerminal
		promptIsTerminal = func() bool { return false }
		t.Cleanup(func() { promptIsTerminal = old })
		err := command.run(context.Background(), &bytes.Buffer{}, args)
		if err == nil || !strings.Contains(err.Error(), "not a terminal") {
			t.Errorf("%s: error = %v", command.name, err)
		}
		if stub.runCalls != 0 {
			t.Errorf("%s: the engine ran without a terminal or -yes", command.name)
		}
	}
}
