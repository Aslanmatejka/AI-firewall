using AiShield.Core.Config;
using AiShield.Core.Models;

namespace AiShield.Core.Permissions;

public sealed class PolicyResolver
{
    private ShieldConfig _config;

    public PolicyResolver(ShieldConfig config) => _config = config;

    public void UpdateConfig(ShieldConfig config) => _config = config;

    public PolicyAction ForResource(ResourceType type)
    {
        var raw = type switch
        {
            ResourceType.Network => _config.NetworkPolicy,
            ResourceType.Clipboard => _config.ClipboardPolicy,
            ResourceType.Screenshot => _config.ScreenshotPolicy,
            ResourceType.Microphone => _config.MicrophonePolicy,
            ResourceType.Camera => _config.CameraPolicy,
            _ => _config.GlobalPolicy,
        };
        return Enum.TryParse<PolicyAction>(raw, true, out var p) ? p : PolicyAction.Ask;
    }
}
