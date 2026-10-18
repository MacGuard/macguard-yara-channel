import SwiftUI

/// Thin wrapper making a busy-gate and its spinner move together.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.N / `_PHASE3_COMPONENT_SPECS.md` §B.14.
/// Base: 8 real `ProgressView(` sites + `model.busy` gating. The real pattern
/// (`if busy { ProgressView().controlSize(.small) }`) is simple enough that this component's
/// only job is making the gate and the spinner inseparable, so a future screen cannot add one
/// without the other.
public struct MGProgressIndicator: View {
    private let isActive: Bool
    private let size: ControlSize

    public init(isActive: Bool, size: ControlSize = .small) {
        self.isActive = isActive
        self.size = size
    }

    public var body: some View {
        if isActive {
            ProgressView()
                .controlSize(size)
        }
    }
}
