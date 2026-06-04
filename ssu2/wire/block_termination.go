package wire

// TerminationReason represents the reason code in a Termination block.
// Spec §Termination defines 23 reason codes (0–22).
type TerminationReason uint8

const (
	TerminationNormalClose           TerminationReason = 0  // Normal close or unspecified
	TerminationReceived              TerminationReason = 1  // Termination received
	TerminationIdleTimeout           TerminationReason = 2  // Idle timeout
	TerminationRouterShutdown        TerminationReason = 3  // Router shutdown
	TerminationDataPhaseAEADFailure  TerminationReason = 4  // Data phase AEAD failure
	TerminationIncompatibleOptions   TerminationReason = 5  // Incompatible options
	TerminationIncompatibleSignature TerminationReason = 6  // Incompatible signature type
	TerminationClockSkew             TerminationReason = 7  // Clock skew
	TerminationPaddingViolation      TerminationReason = 8  // Padding violation
	TerminationAEADFramingError      TerminationReason = 9  // AEAD framing error
	TerminationPayloadFormatError    TerminationReason = 10 // Payload format error
	TerminationSessionRequestError   TerminationReason = 11 // Session request error
	TerminationSessionCreatedError   TerminationReason = 12 // Session created error
	TerminationSessionConfirmedError TerminationReason = 13 // Session confirmed error
	TerminationTimeout               TerminationReason = 14 // Timeout
	TerminationRISigVerifyFail       TerminationReason = 15 // RI signature verification fail
	TerminationSParamMissing         TerminationReason = 16 // s parameter missing, invalid, or mismatched in RouterInfo
	TerminationBanned                TerminationReason = 17 // Banned
	TerminationBadToken              TerminationReason = 18 // Bad token
	TerminationConnectionLimits      TerminationReason = 19 // Connection limits
	TerminationIncompatibleVersion   TerminationReason = 20 // Incompatible version
	TerminationWrongNetID            TerminationReason = 21 // Wrong net ID
	TerminationReplacedByNewSession  TerminationReason = 22 // Replaced by new session
)

// String returns the human-readable name for the termination reason.
func (r TerminationReason) String() string {
	switch r {
	case TerminationNormalClose:
		return "NormalClose"
	case TerminationReceived:
		return "TerminationReceived"
	case TerminationIdleTimeout:
		return "IdleTimeout"
	case TerminationRouterShutdown:
		return "RouterShutdown"
	case TerminationDataPhaseAEADFailure:
		return "DataPhaseAEADFailure"
	case TerminationIncompatibleOptions:
		return "IncompatibleOptions"
	case TerminationIncompatibleSignature:
		return "IncompatibleSignature"
	case TerminationClockSkew:
		return "ClockSkew"
	case TerminationPaddingViolation:
		return "PaddingViolation"
	case TerminationAEADFramingError:
		return "AEADFramingError"
	case TerminationPayloadFormatError:
		return "PayloadFormatError"
	case TerminationSessionRequestError:
		return "SessionRequestError"
	case TerminationSessionCreatedError:
		return "SessionCreatedError"
	case TerminationSessionConfirmedError:
		return "SessionConfirmedError"
	case TerminationTimeout:
		return "Timeout"
	case TerminationRISigVerifyFail:
		return "RISigVerifyFail"
	case TerminationSParamMissing:
		return "SParamMissing"
	case TerminationBanned:
		return "Banned"
	case TerminationBadToken:
		return "BadToken"
	case TerminationConnectionLimits:
		return "ConnectionLimits"
	case TerminationIncompatibleVersion:
		return "IncompatibleVersion"
	case TerminationWrongNetID:
		return "WrongNetID"
	case TerminationReplacedByNewSession:
		return "ReplacedByNewSession"
	default:
		return "Unknown"
	}
}
