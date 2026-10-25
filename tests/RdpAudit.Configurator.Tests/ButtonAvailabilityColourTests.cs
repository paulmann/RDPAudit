/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ButtonAvailabilityColourTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Pins the availability colour contract of the Configurator button theme: the face of an
//          available command button is the sober green ButtonAvailable, an unavailable one is the
//          sober dark red ButtonUnavailable, destructive actions stay red while they are available
//          (a green Delete would read as safe) and still fall back to the unavailable face once they
//          are disabled, and the meaning survives an Enabled flip without the page touching colours.
//          The pure mapping functions are asserted directly, so the contract does not depend on
//          painting a form; one STA test then proves the Enabled toggle really repaints the control.
// Depends: DarkTheme, StaTestHarness, WinForms, xunit

using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;
using RdpAudit.Configurator.Theming;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class ButtonAvailabilityColourTests
{
	[Fact]
	public void AvailableOrdinaryButton_SwitchesFromTheAccentToTheAvailabilityGreen()
	{
		Assert.Equal(DarkTheme.ButtonAvailable, DarkTheme.ButtonBackFor(available: true, DarkTheme.ButtonRole.Ordinary));

		// The old accent blue must no longer be the face of an available command button.
		Assert.NotEqual(DarkTheme.ButtonNormal, DarkTheme.ButtonAvailable);
	}

	[Fact]
	public void UnavailableButton_IsTheSameSoberDarkRedWhateverTheRole()
	{
		Assert.Equal(DarkTheme.ButtonUnavailable, DarkTheme.ButtonBackFor(available: false, DarkTheme.ButtonRole.Ordinary));
		Assert.Equal(DarkTheme.ButtonUnavailable, DarkTheme.ButtonBackFor(available: false, DarkTheme.ButtonRole.Danger));
		Assert.Equal(DarkTheme.ButtonUnavailable, DarkTheme.ButtonBackFor(available: false, DarkTheme.ButtonRole.Success));
	}

	[Fact]
	public void AvailableDestructiveButton_StaysRedSoTheDangerSignalIsNotLost()
	{
		Assert.Equal(DarkTheme.DangerButton, DarkTheme.ButtonBackFor(available: true, DarkTheme.ButtonRole.Danger));
		Assert.Equal(DarkTheme.DangerHover, DarkTheme.ButtonHoverFor(available: true, DarkTheme.ButtonRole.Danger));

		// A destructive button must never borrow the green availability accent: a green hover would
		// read as safe exactly when the pointer invites the click.
		Assert.NotEqual(DarkTheme.ButtonAvailableHover, DarkTheme.ButtonHoverFor(available: true, DarkTheme.ButtonRole.Danger));
	}

	[Fact]
	public void AvailableConfirmingButton_KeepsTheSuccessFace()
	{
		Assert.Equal(DarkTheme.SuccessAccent, DarkTheme.ButtonBackFor(available: true, DarkTheme.ButtonRole.Success));
	}

	[Fact]
	public void AvailableOrdinaryButton_HoversBrighterAndUnavailableDoesNotLightUp()
	{
		Assert.Equal(DarkTheme.ButtonAvailableHover, DarkTheme.ButtonHoverFor(available: true, DarkTheme.ButtonRole.Ordinary));
		Assert.Equal(DarkTheme.ButtonUnavailableBorder, DarkTheme.ButtonHoverFor(available: false, DarkTheme.ButtonRole.Ordinary));
	}

	[Fact]
	public void Palette_KeepsGreenDarkAndRedSoberRatherThanNeon()
	{
		// "Sober" is a contract, not a taste: both faces must stay dark enough for light text and
		// must not be saturated alarm colours.
		Assert.True(DarkTheme.ButtonAvailable.GetBrightness() < 0.5f);
		Assert.True(DarkTheme.ButtonUnavailable.GetBrightness() < 0.5f);
		Assert.True(DarkTheme.ButtonAvailable.G > DarkTheme.ButtonAvailable.R);
		Assert.True(DarkTheme.ButtonUnavailable.R > DarkTheme.ButtonUnavailable.G);
	}

	[Fact]
	public void ApplyButtonState_PaintsFaceBorderAndHoverForTheCurrentAvailability()
	{
		using Button button = new() { Enabled = false };

		DarkTheme.ApplyButtonState(button, DarkTheme.ButtonRole.Ordinary);

		Assert.Equal(DarkTheme.ButtonUnavailable, button.BackColor);
		Assert.Equal(DarkTheme.ButtonUnavailableBorder, button.FlatAppearance.BorderColor);
		Assert.Equal(DarkTheme.ButtonUnavailable, button.FlatAppearance.MouseOverBackColor);
		Assert.Equal(FlatStyle.Flat, button.FlatStyle);

		button.Enabled = true;
		DarkTheme.ApplyButtonState(button, DarkTheme.ButtonRole.Ordinary);

		Assert.Equal(DarkTheme.ButtonAvailable, button.BackColor);
		Assert.Equal(DarkTheme.ButtonAvailableHover, button.FlatAppearance.MouseOverBackColor);
	}

	[Fact]
	public void ApplyButtonState_DisabledButton_KeepsLightTextOnTheDarkFace()
	{
		using Button button = new() { Enabled = false };

		DarkTheme.ApplyButtonState(button, DarkTheme.ButtonRole.Ordinary);

		Assert.Equal(DarkTheme.TextPrimary, button.ForeColor);
	}

	[Fact]
	public void StyleButton_BindsTheFaceToAvailabilityWithoutPageCode()
	{
		StaTestHarness ui = new(nameof(ButtonAvailabilityColourTests));
		ui.Run(() =>
		{
			using Button button = new() { Enabled = true };
			DarkTheme.StyleButton(button);
			Assert.Equal(DarkTheme.ButtonAvailable, button.BackColor);

			// No page code touches the colour: flipping Enabled is enough.
			button.Enabled = false;
			Assert.Equal(DarkTheme.ButtonUnavailable, button.BackColor);

			button.Enabled = true;
			Assert.Equal(DarkTheme.ButtonAvailable, button.BackColor);
		});
	}

	[Fact]
	public void StyleButton_RemembersTheDangerMeaningAcrossAnEnabledFlip()
	{
		StaTestHarness ui = new(nameof(ButtonAvailabilityColourTests));
		ui.Run(() =>
		{
			using Button button = new() { Enabled = true, BackColor = DarkTheme.DangerButton };
			DarkTheme.StyleButton(button, DarkTheme.DangerButton, DarkTheme.DangerHover);
			Assert.Equal(DarkTheme.DangerButton, button.BackColor);

			button.Enabled = false;
			Assert.Equal(DarkTheme.ButtonUnavailable, button.BackColor);

			// Re-enabling restores the danger face, not the ordinary green.
			button.Enabled = true;
			Assert.Equal(DarkTheme.DangerButton, button.BackColor);
		});
	}

	[Fact]
	public void StyleButton_IsIdempotent()
	{
		StaTestHarness ui = new(nameof(ButtonAvailabilityColourTests));
		ui.Run(() =>
		{
			using Button button = new() { Enabled = true };
			DarkTheme.StyleButton(button);
			DarkTheme.StyleButton(button);
			DarkTheme.StyleButton(button);

			Assert.Equal(DarkTheme.ButtonAvailable, button.BackColor);

			// Exactly one subscription survives the re-styling, so one toggle is one repaint.
			button.Enabled = false;
			Assert.Equal(DarkTheme.ButtonUnavailable, button.BackColor);
			button.Enabled = true;
			Assert.Equal(DarkTheme.ButtonAvailable, button.BackColor);
		});
	}
}
