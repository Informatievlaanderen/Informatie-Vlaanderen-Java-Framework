/*
 * AGIV Java Security Project.
 * Copyright (C) 2011-2012 AGIV.
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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Calendar;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;

/**
 * Swing status bar with clock and status label.
 * 
 * @author Frank Cornelis
 * 
 */
public class StatusBar extends JPanel implements ActionListener {

	private static final long serialVersionUID = 1L;

	private final JPanel statusLabelPanel;

	private final JPanel statusClockPanel;

	private final JLabel statusClock;

	private final FadeLabel statusLabel;

	private String time;

	private String date;

	public StatusBar() {
		setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED,
				Color.WHITE, Color.GRAY));

		this.statusLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		this.statusLabelPanel.setBorder(BorderFactory.createBevelBorder(
				BevelBorder.LOWERED, Color.WHITE, Color.GRAY));

		this.statusLabel = new FadeLabel();
		this.statusLabelPanel.add(this.statusLabel);

		this.statusClockPanel = new JPanel();
		this.statusClockPanel.setBorder(BorderFactory.createBevelBorder(
				BevelBorder.LOWERED, Color.WHITE, Color.GRAY));

		this.statusClock = new JLabel();
		this.statusClockPanel.add(this.statusClock);

		GridBagLayout gridbag = new GridBagLayout();
		GridBagConstraints c = new GridBagConstraints();
		setLayout(gridbag);

		c.fill = GridBagConstraints.BOTH;
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 1;
		c.weightx = 1.0;
		c.anchor = GridBagConstraints.WEST;
		gridbag.setConstraints(this.statusLabelPanel, c);
		add(this.statusLabelPanel);

		c.gridx = GridBagConstraints.RELATIVE;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.EAST;
		c.gridwidth = GridBagConstraints.REMAINDER;
		c.weightx = 0.0;
		gridbag.setConstraints(this.statusClockPanel, c);
		add(this.statusClockPanel);

		new Timer(1000, this).start();
		actionPerformed(null);
	}

	public void setStatus(String statusMessage) {
		this.statusLabel.setText(statusMessage);
	}

	public void actionPerformed(ActionEvent evt) {
		String currTime = getTime();
		if (!currTime.equals(this.time)) {
			this.time = currTime;
			this.statusClock.setText(this.time);
			String currDate = getDate();
			if (!currDate.equals(this.date)) {
				this.date = currDate;
				this.statusClock.setToolTipText(this.date);
			}
		}
	}

	private String getTime() {
		Calendar calendar = Calendar.getInstance();
		return calendar.get(Calendar.HOUR_OF_DAY) + ":"
				+ calendar.get(Calendar.MINUTE) + ":"
				+ calendar.get(Calendar.SECOND);
	}

	private String getDate() {
		Calendar calendar = Calendar.getInstance();
		return calendar.get(Calendar.DAY_OF_MONTH) + "/"
				+ (calendar.get(Calendar.MONTH) + 1) + "/"
				+ calendar.get(Calendar.YEAR);
	}

	public void setErrorStatus(String message) {
		this.statusLabel.setText(message, Color.RED);
	}
}
