/*
 * Informatie Vlaanderen Java Security Project.
 * Copyright (C) 2011-2017 Informatie Vlaanderen.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.agiv.security.demo;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JLabel;
import javax.swing.Timer;

/**
 * A Swing label that features automatic fading.
 * 
 * @author Frank Cornelis
 * 
 */
public class FadeLabel extends JLabel implements ActionListener {

	private static final long serialVersionUID = 1L;

	private Timer timer;
	private static final int STEPS = 15;
	private static final int DEFAULT_INITIAL_DELAY = 2 * 1000;
	private int dR, dG, dB;
	private int counter;

	public FadeLabel() {
		this.timer = new Timer(50, this);
	}

	public void actionPerformed(ActionEvent e) {
		Color c = getForeground();
		c = new Color(c.getRed() + this.dR, c.getGreen() + this.dG, c.getBlue()
				+ this.dB);
		setForeground(c);
		if (this.counter >= STEPS) {
			this.timer.stop();
			setForeground(getBackground());
		}
		this.counter++;
	}

	public void setText(String text) {
		setText(text, Color.BLACK);
	}

	public void setText(String text, Color beginColor) {
		setText(text, beginColor, DEFAULT_INITIAL_DELAY);
	}

	public void setText(String text, int delay) {
		setText(text, Color.BLACK, delay);
	}

	public synchronized void setText(String text, Color beginColor, int delay) {
		if (this.timer == null) {
			return;
		}
		this.timer.stop();
		super.setText(text);
		setForeground(beginColor);
		this.timer.setInitialDelay(delay);
		Color endColor = getBackground();
		this.dR = (endColor.getRed() - beginColor.getRed()) / STEPS;
		this.dB = (endColor.getBlue() - beginColor.getBlue()) / STEPS;
		this.dG = (endColor.getGreen() - beginColor.getGreen()) / STEPS;
		this.counter = 0;
		this.timer.start();
	}
}
